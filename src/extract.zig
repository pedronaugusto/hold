//! Extraction into a directory, for every format, with the hostile-input
//! rules on (design §3): names checked, parents opened a component at a
//! time without following links, files written through airlock (a temp
//! beside the name, published by rename, `batch_len` at a time under one
//! barrier), links created after every file and only where they stay
//! inside, specials refused, permissions as Python's `data` filter leaves
//! them, every byte bounded.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const aegis = @import("aegis");
const airlock = @import("airlock");
const Entry = @import("Entry.zig");
const Limits = @import("Limits.zig");
const Diagnostic = @import("Diagnostic.zig");
const name_ = @import("name.zig");
const TarReader = @import("tar/Reader.zig");
const ZipArchive = @import("zip/Archive.zig");
const ZipStream = @import("zip/Stream.zig");
const SevenzArchive = @import("sevenz/Archive.zig");

/// The archive to extract, already opened.
pub const Source = union(enum) {
    tar: *TarReader,
    zip: *ZipArchive,
    zip_stream: *ZipStream,
    /// Its password, for AES folders, is the archive's own (`open`'s).
    sevenz: *SevenzArchive,
};

pub const Options = struct {
    /// What each file and link is made durable to; `.none` is what every
    /// rival does by default.
    level: airlock.Level = .none,
    links: Links = .contained,
    specials: Specials = .refuse,
    mode: Mode = .data,
    /// Set each file's and directory's modification time to the archive's.
    times: bool = true,
    /// The most bytes the extraction writes, all entries together.
    total: ?Limits.Bytes = null,
    /// For AES-encrypted zip entries; a 7z archive takes its password
    /// when it is opened.
    password: ?*const aegis.SecretBytes = null,
    diagnostic: ?*Diagnostic = null,
};

pub const Links = enum {
    /// A symbolic link is made only when its target stays inside the
    /// destination however it is followed (`name.checkLink`); a hard link
    /// only to a file this extraction wrote.
    contained,
    /// No links at all: a link entry is refused.
    refuse,
    /// Symbolic links as the archive says, wherever they point. Hard links
    /// are still held to files this extraction wrote.
    any_unsafe,
};

pub const Specials = enum {
    /// A device, a FIFO or an entry of kind `other` is `error.Special`.
    refuse,
    /// Passed over and counted.
    skip,
};

pub const Mode = enum {
    /// As Python's `data` filter: no set-user-ID, set-group-ID or sticky
    /// bit, no write for group or others, and the owner can always read
    /// and write (and enter a directory).
    data,
    /// The archive's permission bits, special bits included.
    exact_unsafe,
};

/// What an extraction did.
pub const Summary = struct {
    files: u64 = 0,
    directories: u64 = 0,
    links: u64 = 0,
    skipped: u64 = 0,
    bytes: u64 = 0,
};

pub const Error = error{
    /// A name with a way out of the destination (`name.check`).
    UnsafeName,
    /// A symbolic link that could lead out, or a hard link to anything but
    /// a file this extraction wrote; any link under `.refuse`.
    UnsafeLink,
    /// A parent of the entry is a symbolic link or not a directory.
    ThroughLink,
    /// A device, a FIFO or an `other` entry under `.refuse`.
    Special,
    /// More bytes than `Options.total`.
    LimitExceeded,
    /// The archive is malformed, truncated, or an entry's contents fail
    /// their CRC, size or MAC check; `Diagnostic` says which.
    Invalid,
    Truncated,
    Corrupt,
    /// A method warp has no decoder for, or an encryption hold refuses.
    UnsupportedMethod,
    UnsupportedEncryption,
    PasswordRequired,
    WrongPassword,
    /// Something of the archive the reader refuses (`zip.Stream`'s stored
    /// entries with descriptors).
    Unsupported,
    Canceled,
    ReadFailed,
    OutOfMemory,
} || FsError;

/// The filesystem's errors, from the calls extraction makes.
pub const FsError = airlock.CreateError || airlock.Batch.Error || airlock.SymLinkError || Io.Dir.OpenError || Io.Dir.CreateDirError ||
    Io.Dir.HardLinkError || Io.Dir.DeleteFileError || Io.Dir.SetTimestampsError || Io.Dir.SetFilePermissionsError || Io.File.WritePositionalError || Io.Writer.Error;

/// How many files and directories one airlock batch makes durable
/// together. Each file's temp and parent stay open until its batch
/// commits, so a batch holds about twice this many descriptors.
pub const batch_len = 32;

/// Extracts every entry of `source` into `dir`.
pub fn extract(io: Io, gpa: Allocator, dir: Io.Dir, source: Source, options: Options) Error!Summary {
    const publish = try gpa.create(Publish);
    defer gpa.destroy(publish);
    publish.* = .{ .batch = .init(&publish.slots) };
    var x: Extraction = .{ .io = io, .gpa = gpa, .root = dir, .options = options, .walk = .{ .source = source }, .publish = publish };
    defer x.deinit();
    while (try x.walk.next(io, gpa, options)) |item| {
        try io.checkCancel();
        try x.one(item);
    }
    // Every file is published before a hard link may name it.
    try x.commit();
    try x.links();
    try x.directories();
    try x.commit();
    return x.summary;
}

/// The batch files and directories are made durable in: its slots, the
/// pendings it holds, and for each slot the entry it came from.
const Publish = struct {
    slots: [batch_len]airlock.Batch.Slot = undefined,
    pendings: [batch_len]airlock.Pending = undefined,
    entries: [batch_len]u64 = undefined,
    batch: airlock.Batch,
    used: u32 = 0,
    pending_count: u32 = 0,
    /// Parents of this batch's pendings, open until it commits: a pending
    /// is renamed through the directory it was created in.
    held: std.ArrayList(Io.Dir) = .empty,
    /// The last directory added, so a run of entries in one adds it once.
    last_dir: ?[]const u8 = null,
};

const Extraction = struct {
    io: Io,
    gpa: Allocator,
    root: Io.Dir,
    options: Options,
    walk: Walk,
    publish: *Publish,
    summary: Summary = .{},
    /// The deferred work's strings.
    arena: std.heap.ArenaAllocator.State = .{},
    /// Files this extraction wrote, which hard links may name.
    written: std.StringHashMapUnmanaged(void) = .empty,
    symlinks: std.ArrayList(Deferred) = .empty,
    hardlinks: std.ArrayList(Deferred) = .empty,
    dirs: std.ArrayList(DirFix) = .empty,
    /// The last parent opened, kept for the next entry in it.
    cached: ?struct { path: []u8, dir: Io.Dir, held: bool } = null,

    const Deferred = struct { path: []const u8, target: []const u8, entry: u64 };
    const DirFix = struct { path: []const u8, mode: ?u32, mtime: ?Io.Timestamp, entry: u64 };

    fn deinit(x: *Extraction) void {
        x.walk.deinit();
        // After a failure: the batch's pendings are discarded.
        x.publish.batch.reset(x.io);
        x.release();
        x.publish.held.deinit(x.gpa);
        if (x.cached) |c| {
            c.dir.close(x.io);
            x.gpa.free(c.path);
        }
        x.written.deinit(x.gpa);
        x.symlinks.deinit(x.gpa);
        x.hardlinks.deinit(x.gpa);
        x.dirs.deinit(x.gpa);
        x.arena.promote(x.gpa).deinit();
    }

    fn dupe(x: *Extraction, s: []const u8) Allocator.Error![]const u8 {
        var arena = x.arena.promote(x.gpa);
        defer x.arena = arena.state;
        return arena.allocator().dupe(u8, s);
    }

    fn fail(x: *Extraction, reason: Diagnostic.Reason, e: anytype) @TypeOf(e) {
        Diagnostic.set(x.options.diagnostic, x.walk.index, 0, reason);
        return e;
    }

    fn one(x: *Extraction, item: Walk.Item) Error!void {
        const e = item.entry;
        // A 7z anti item deletes a file in an update: never extracted.
        if (item.anti) {
            x.summary.skipped += 1;
            return;
        }
        var buffer: [name_.max_len]u8 = undefined;
        const path = (name_.check(e.name, &buffer) catch return x.fail(.unsafe_name, error.UnsafeName)) orelse {
            // The destination itself (`./`): nothing to make.
            return;
        };
        switch (e.kind) {
            .directory => {
                var d = try x.makeDirs(path);
                d.close(x.io);
                try x.dirs.append(x.gpa, .{ .path = try x.dupe(path), .mode = e.mode, .mtime = e.mtime, .entry = x.walk.index });
                x.summary.directories += 1;
            },
            .file => try x.file(path, e, item.contents.?),
            .symlink => {
                if (x.options.links == .refuse) return x.fail(.unsafe_link, error.UnsafeLink);
                const target = if (item.link_contents) |l| l else e.link;
                try x.symlinks.append(x.gpa, .{ .path = try x.dupe(path), .target = try x.dupe(target), .entry = x.walk.index });
            },
            .hardlink => {
                if (x.options.links == .refuse) return x.fail(.unsafe_link, error.UnsafeLink);
                var target_buffer: [name_.max_len]u8 = undefined;
                const target = (name_.check(e.link, &target_buffer) catch return x.fail(.unsafe_link, error.UnsafeLink)) orelse return x.fail(.unsafe_link, error.UnsafeLink);
                try x.hardlinks.append(x.gpa, .{ .path = try x.dupe(path), .target = try x.dupe(target), .entry = x.walk.index });
            },
            .character_device, .block_device, .fifo, .other => switch (x.options.specials) {
                .refuse => return x.fail(.special, error.Special),
                .skip => x.summary.skipped += 1,
            },
        }
    }

    /// A file, written to a temp beside its name and published by rename
    /// when its batch commits, so a name that was a link is replaced,
    /// never followed.
    fn file(x: *Extraction, path: []const u8, e: Entry, contents: *Io.Reader) Error!void {
        try x.room();
        const split = splitPath(path);
        const parent = try x.parentOf(split.dir);
        const p = x.publish;
        // The batch borrows the name until it commits.
        const base = try x.dupe(split.base);
        const pending = &p.pendings[p.pending_count];
        pending.* = try airlock.create(x.io, parent, base, .{ .mode = .{ .exact = permissions(x.fileMode(e.mode)) } });
        var in_batch = false;
        defer if (!in_batch) pending.discard(x.io);
        var buffer: [64 * 1024]u8 = undefined;
        const w = pending.writer(x.io, &buffer);
        while (true) {
            // A coarse step: one cancel check a MiB.
            try x.io.checkCancel();
            const n = contents.stream(w, .limited(1 << 20)) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return x.walk.contentsError(),
                error.WriteFailed => return writeError(pending.cause()),
            };
            x.summary.bytes += n;
            if (x.options.total) |limit| if (Limits.over(limit, x.summary.bytes)) return x.fail(.entry_limit, error.LimitExceeded);
        }
        w.flush() catch return writeError(pending.cause());
        if (x.options.times) if (e.mtime) |t| {
            try pending.file().setTimestamps(x.io, .{ .modify_timestamp = .{ .new = t }, .access_timestamp = .init(e.atime) });
        };
        p.batch.addPending(x.io, pending, .replace) catch unreachable; // unreachable: `room` made space
        in_batch = true;
        p.pending_count += 1;
        x.added(x.walk.index);
        x.cached.?.held = true;
        try x.written.put(x.gpa, try x.dupe(path), {});
        x.summary.files += 1;
    }

    /// A free slot in the batch, committing it when full.
    fn room(x: *Extraction) Error!void {
        if (x.publish.used == batch_len) try x.commit();
    }

    fn added(x: *Extraction, entry: u64) void {
        x.publish.entries[x.publish.used] = entry;
        x.publish.used += 1;
    }

    /// A directory whose entries or metadata changed, made durable with
    /// the batch. Its path is borrowed until the batch commits; nothing in
    /// it is a link the extraction made, since links come after the files
    /// and only at leaves.
    fn touch(x: *Extraction, path: []const u8, entry: u64) Error!void {
        if (x.options.level == .none) return;
        if (x.publish.last_dir) |last| if (std.mem.eql(u8, last, path)) return;
        try x.room();
        const owned = try x.dupe(if (path.len == 0) "." else path);
        x.publish.batch.addDirPath(x.root, owned) catch unreachable; // unreachable: `room` made space
        x.added(entry);
        x.publish.last_dir = owned;
    }

    /// Makes the batch durable at the level: renames its pendings in
    /// order and syncs what it holds, under one barrier.
    fn commit(x: *Extraction) Error!void {
        const p = x.publish;
        defer x.release();
        _ = p.batch.commit(x.io, .{ .level = x.options.level }) catch |err| {
            if (p.batch.failure()) |f| {
                const entry = (f.slot.get(p.entries[0..p.used]) catch unreachable).*; // unreachable: a failed slot was added
                Diagnostic.set(x.options.diagnostic, entry, 0, .filesystem);
            }
            p.batch.reset(x.io);
            return err;
        };
    }

    /// Closes the parents the batch held and empties it.
    fn release(x: *Extraction) void {
        const p = x.publish;
        for (p.held.items) |d| d.close(x.io);
        p.held.clearRetainingCapacity();
        if (x.cached) |*c| c.held = false;
        p.used = 0;
        p.pending_count = 0;
        p.last_dir = null;
    }

    fn fileMode(x: *const Extraction, mode: ?u32) u32 {
        const m = mode orelse 0o644;
        return switch (x.options.mode) {
            .data => (m | 0o600) & 0o755,
            .exact_unsafe => m & 0o7777,
        };
    }

    fn dirMode(x: *const Extraction, mode: ?u32) u32 {
        const m = mode orelse 0o755;
        return switch (x.options.mode) {
            .data => (m | 0o700) & 0o755,
            .exact_unsafe => m & 0o7777,
        };
    }

    /// Symbolic links, then hard links, after every file: no later entry
    /// is ever written through one.
    fn links(x: *Extraction) Error!void {
        for (x.symlinks.items) |l| {
            if (x.options.links == .contained) name_.checkLink(l.path, l.target) catch {
                Diagnostic.set(x.options.diagnostic, l.entry, 0, .unsafe_link);
                return error.UnsafeLink;
            };
            const split = splitPath(l.path);
            const parent = try x.parentOf(split.dir);
            // Made durable with the batch, through its directory.
            _ = try airlock.symLink(x.io, parent, l.target, split.base, .{ .sync = .{ .level = .none } });
            try x.touch(split.dir, l.entry);
            x.summary.links += 1;
        }
        for (x.hardlinks.items) |l| {
            if (!x.written.contains(l.target)) {
                Diagnostic.set(x.options.diagnostic, l.entry, 0, .unsafe_link);
                return error.UnsafeLink;
            }
            const from = splitPath(l.target);
            var from_dir = try x.openDirs(from.dir, false);
            defer from_dir.close(x.io);
            const to = splitPath(l.path);
            const to_dir = try x.parentOf(to.dir);
            to_dir.deleteFile(x.io, to.base) catch |err| switch (err) {
                error.FileNotFound => {},
                else => |other| return other,
            };
            try from_dir.hardLink(from.base, to_dir, to.base, x.io, .{ .follow_symlinks = false });
            try x.touch(to.dir, l.entry);
            x.summary.links += 1;
        }
    }

    /// Directories' permissions and times, last and deepest first: writing
    /// a directory's entries changes its time, and a read-only directory
    /// must still take them.
    fn directories(x: *Extraction) Error!void {
        var i = x.dirs.items.len;
        while (i > 0) {
            i -= 1;
            const d = x.dirs.items[i];
            const split = splitPath(d.path);
            const parent = try x.parentOf(split.dir);
            if (builtin.os.tag != .windows) try parent.setFilePermissions(x.io, split.base, permissions(x.dirMode(d.mode)), .{ .follow_symlinks = false });
            if (x.options.times) if (d.mtime) |t| {
                try parent.setTimestamps(x.io, split.base, .{ .follow_symlinks = false, .modify_timestamp = .{ .new = t } });
            };
            try x.touch(d.path, d.entry);
        }
    }

    /// The directory `path` names, made where missing; the last one is
    /// kept open for the entries that follow in it.
    fn parentOf(x: *Extraction, path: []const u8) Error!Io.Dir {
        if (x.cached) |c| {
            if (std.mem.eql(u8, c.path, path)) return c.dir;
            // A parent of a pending stays open until its batch commits.
            if (c.held) try x.publish.held.append(x.gpa, c.dir) else c.dir.close(x.io);
            x.gpa.free(c.path);
            x.cached = null;
        }
        const d = try x.makeDirs(path);
        errdefer d.close(x.io);
        x.cached = .{ .path = try x.gpa.dupe(u8, path), .dir = d, .held = false };
        return d;
    }

    fn makeDirs(x: *Extraction, path: []const u8) Error!Io.Dir {
        return x.openDirs(path, true);
    }

    /// Opens `path` a component at a time, never following a link: a
    /// component that is a link, or a file, is `error.ThroughLink`.
    fn openDirs(x: *Extraction, path: []const u8, create: bool) Error!Io.Dir {
        var d = try x.root.openDir(x.io, ".", .{});
        if (path.len == 0) return d;
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |part| {
            const at = it.index orelse path.len + 1;
            const next = d.openDir(x.io, part, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => blk: {
                    if (!create) {
                        d.close(x.io);
                        return err;
                    }
                    d.createDir(x.io, part, permissions(0o755)) catch |c| switch (c) {
                        error.PathAlreadyExists => {},
                        else => |other| {
                            d.close(x.io);
                            return other;
                        },
                    };
                    // The directory it was made in gained a name.
                    const start = at - 1 - part.len;
                    x.touch(if (start == 0) "" else path[0 .. start - 1], x.walk.index) catch |t| {
                        d.close(x.io);
                        return t;
                    };
                    break :blk d.openDir(x.io, part, .{ .follow_symlinks = false }) catch |again| {
                        d.close(x.io);
                        return through(again);
                    };
                },
                else => |other| {
                    d.close(x.io);
                    return through(other);
                },
            };
            d.close(x.io);
            d = next;
        }
        return d;
    }
};

/// The file error behind a temp's `WriteFailed`, which airlock keeps.
fn writeError(cause: ?anyerror) Error {
    const c = cause orelse return error.WriteFailed;
    inline for (@typeInfo(Io.File.WritePositionalError).error_set.error_names.?) |n| {
        if (c == @field(anyerror, n)) return @field(Io.File.WritePositionalError, n);
    }
    return error.WriteFailed;
}

/// A link or a file where a directory was wanted.
fn through(err: Io.Dir.OpenError) Error {
    return switch (err) {
        error.SymLinkLoop, error.NotDir => error.ThroughLink,
        else => |other| other,
    };
}

fn splitPath(path: []const u8) struct { dir: []const u8, base: []const u8 } {
    const slash = std.mem.findScalarLast(u8, path, '/') orelse return .{ .dir = "", .base = path };
    return .{ .dir = path[0..slash], .base = path[slash + 1 ..] };
}

fn permissions(mode: u32) Io.File.Permissions {
    if (@hasDecl(Io.File.Permissions, "fromMode")) return .fromMode(@intCast(mode));
    return .default_file;
}

/// Each format's entries and contents, one at a time.
const Walk = struct {
    source: Source,
    index: u64 = 0,
    /// zip through the central directory: where the records are, the
    /// open entry's contents and its local extra fields.
    records: ?ZipArchive.Iterator = null,
    zip_contents: ZipArchive.Contents = undefined,
    zip_open: bool = false,
    local_extra: std.ArrayList(u8) = .empty,
    /// A zip symbolic link's target, read from its contents.
    link_buffer: std.ArrayList(u8) = .empty,
    /// The next 7z item.
    sevenz_next: usize = 0,
    gpa: Allocator = undefined,

    const Item = struct {
        entry: Entry,
        contents: ?*Io.Reader,
        link_contents: ?[]const u8 = null,
        anti: bool = false,
    };

    fn deinit(w: *Walk) void {
        if (w.zip_open) w.zip_contents.deinit();
        w.local_extra.deinit(w.gpa);
        w.link_buffer.deinit(w.gpa);
    }

    fn next(w: *Walk, io: Io, gpa: Allocator, options: Options) Error!?Item {
        _ = io;
        w.gpa = gpa;
        w.index += 1;
        switch (w.source) {
            .tar => |r| {
                const e = (r.next() catch |err| return mapTar(err)) orelse return null;
                return .{ .entry = e, .contents = r.contents() };
            },
            .zip_stream => |s| {
                const r = (s.next() catch |err| return mapStream(err)) orelse return null;
                var item: Item = .{ .entry = r.entry, .contents = s.contents() };
                if (r.entry.kind == .symlink) item.link_contents = try w.readLink(s.contents(), options);
                return item;
            },
            .zip => |a| {
                if (w.records == null) w.records = a.iterate();
                if (w.zip_open) {
                    w.zip_contents.deinit();
                    w.zip_open = false;
                }
                const central = w.records.?.next() orelse return null;
                const r = a.local(central, &w.local_extra) catch |err| return switch (err) {
                    error.Invalid => error.Invalid,
                    error.LimitExceeded => error.LimitExceeded,
                    error.Truncated => error.Truncated,
                    error.ReadFailed => error.ReadFailed,
                    error.OutOfMemory => error.OutOfMemory,
                };
                var item: Item = .{ .entry = r.entry, .contents = null };
                if (r.entry.kind == .file or r.entry.kind == .symlink) {
                    a.contents(&w.zip_contents, r, &.{}, .{ .password = options.password }) catch |err| return mapContents(err);
                    w.zip_open = true;
                    item.contents = w.zip_contents.reader();
                    if (r.entry.kind == .symlink) item.link_contents = try w.readLink(item.contents.?, options);
                }
                return item;
            },
            .sevenz => |a| {
                const items = a.entries();
                if (w.sevenz_next == items.len) return null;
                const it = items[w.sevenz_next];
                w.sevenz_next += 1;
                var item: Item = .{ .entry = it.entry, .contents = null, .anti = it.anti };
                if (it.anti) return item;
                item.contents = a.contents(it, &.{}) catch |err| return mapSevenz(err);
                if (it.entry.kind == .symlink) item.link_contents = try w.readLink(item.contents.?, options);
                return item;
            },
        }
    }

    /// A zip link's target: its contents, bounded as a header is.
    fn readLink(w: *Walk, r: *Io.Reader, options: Options) Error![]const u8 {
        _ = options;
        w.link_buffer.clearRetainingCapacity();
        var aw: Io.Writer.Allocating = .fromArrayList(w.gpa, &w.link_buffer);
        defer w.link_buffer = aw.toArrayList();
        _ = r.streamRemaining(&aw.writer) catch |err| switch (err) {
            error.ReadFailed => return w.contentsError(),
            error.WriteFailed => return error.OutOfMemory,
        };
        if (aw.written().len > name_.max_len) return error.UnsafeLink;
        return aw.written();
    }

    /// What was wrong behind a contents reader's `ReadFailed`.
    fn contentsError(w: *Walk) Error {
        switch (w.source) {
            .tar => |r| if (r.err()) |e| return switch (e) {
                error.Truncated => error.Truncated,
            },
            .zip_stream => |s| if (s.err()) |e| return switch (e) {
                error.Truncated => error.Truncated,
                error.LimitExceeded => error.LimitExceeded,
                else => error.Corrupt,
            },
            .zip => if (w.zip_open) if (w.zip_contents.err()) |e| return switch (e) {
                error.Truncated => error.Truncated,
                else => error.Corrupt,
            },
            .sevenz => |a| if (a.err()) |e| return switch (e) {
                error.Truncated => error.Truncated,
                error.WrongPassword => error.WrongPassword,
                else => error.Corrupt,
            },
        }
        return error.ReadFailed;
    }
};

fn mapTar(err: TarReader.NextError) Error {
    return switch (err) {
        error.Invalid => error.Invalid,
        error.Truncated => error.Truncated,
        error.LimitExceeded => error.LimitExceeded,
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn mapStream(err: ZipStream.NextError) Error {
    return switch (err) {
        error.Invalid => error.Invalid,
        error.Unsupported => error.Unsupported,
        error.LimitExceeded => error.LimitExceeded,
        error.Truncated => error.Truncated,
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn mapContents(err: ZipArchive.ContentsError) Error {
    return switch (err) {
        error.Invalid => error.Invalid,
        error.UnsupportedMethod => error.UnsupportedMethod,
        error.UnsupportedEncryption => error.UnsupportedEncryption,
        error.PasswordRequired => error.PasswordRequired,
        error.WrongPassword => error.WrongPassword,
        error.LimitExceeded => error.LimitExceeded,
        error.Truncated => error.Truncated,
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn mapSevenz(err: SevenzArchive.ContentsError) Error {
    return switch (err) {
        error.Invalid => error.Invalid,
        error.UnsupportedMethod => error.UnsupportedMethod,
        error.UnsupportedEncryption => error.UnsupportedEncryption,
        error.PasswordRequired => error.PasswordRequired,
        error.LimitExceeded => error.LimitExceeded,
        error.Corrupt => error.Corrupt,
        error.Truncated => error.Truncated,
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}
