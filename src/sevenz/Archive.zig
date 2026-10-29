//! A 7z archive, read (design §0): the start header, the header (encoded
//! headers decoded first), and each entry's contents from its folder.
//! Entries of one folder share a stream (a solid archive): reading them
//! in order decodes it once, and an entry out of order decodes its folder
//! again from the start up to it.
const Archive = @This();

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const aegis = @import("aegis");
const warp = @import("warp");
const header = @import("header.zig");
const aes = @import("aes.zig");
const codec = @import("../codec.zig");
const Limits = @import("../Limits.zig");
const Diagnostic = @import("../Diagnostic.zig");
const Bounded = @import("../Bounded.zig");
const Checked = @import("../Checked.zig");
const Entry = @import("../Entry.zig");
const text = @import("../text.zig");
const time = @import("../time.zig");

/// Where the archive's bytes are.
pub const Source = @import("../source.zig").Source;

pub const Options = struct {
    limits: Limits = .{},
    diagnostic: ?*Diagnostic = null,
    /// For AES-encrypted folders, and an encrypted header.
    password: ?*const aegis.SecretBytes = null,
};

/// The coders 7z names, by their IDs.
pub const coder = struct {
    pub const copy = 0x00;
    pub const delta = 0x03;
    pub const lzma2 = 0x21;
    pub const lzma = 0x030101;
    pub const x86 = 0x03030103;
    pub const powerpc = 0x03030205;
    pub const ia64 = 0x03030401;
    pub const arm = 0x03030501;
    pub const armthumb = 0x03030701;
    pub const sparc = 0x03030805;
    pub const arm64 = 0x0a;
    pub const riscv = 0x0b;
    pub const bcj2 = 0x0303011b;
    pub const ppmd = 0x030401;
    pub const deflate = 0x040108;
    pub const deflate64 = 0x040109;
    pub const bzip2 = 0x040202;
    pub const zstd = 0x04f71101;
    pub const aes256 = 0x06f10701;
};

/// The coders one folder may chain; 7-Zip writes at most four.
const max_chain = 8;
/// The packed streams one folder may read side by side: BCJ2's four.
const max_packs = 4;
/// Encoded headers inside encoded headers: 7-Zip writes one.
const max_encodings = 4;

/// One entry and where its contents are.
pub const Item = struct {
    entry: Entry,
    /// The entry's place in the archive, from zero.
    index: u32,
    /// The folder of its contents; null for an entry without any.
    folder: ?u32 = null,
    /// Its substream within the folder.
    stream: u32 = 0,
    crc: ?u32 = null,
    /// Windows attributes, with a Unix mode in the high 16 bits when
    /// 0x8000 is set.
    attributes: ?u32 = null,
    /// An entry an update deletes: never extracted.
    anti: bool = false,
    /// Its folder decrypts with the password.
    encrypted: bool = false,
};

gpa: Allocator,
source: Source,
options: Options,
/// Private: the header's structures, names and the decoded header.
arena: std.heap.ArenaAllocator,
streams: header.Streams = .{},
/// Private: where each packed stream starts in the archive.
pack_starts: []const u64 = &.{},
items: []Item = &.{},
/// Private: the folder being read, while there is one.
cursor: ?*Cursor = null,
/// Private: the reader of an entry without contents.
empty: Io.Reader = .fixed(""),
/// Private: the coder refused last, for the diagnostic.
refused: u64 = 0,

pub const OpenError = error{
    /// Not a 7z archive, or a header that breaks the format.
    Invalid,
    /// The header's CRC is wrong, or an encoded header decodes wrong.
    Corrupt,
    /// Additional streams or external header data, which no writer uses.
    Unsupported,
    /// The header is encoded with a coder warp has no decoder for yet.
    UnsupportedMethod,
    UnsupportedEncryption,
    PasswordRequired,
    WrongPassword,
    /// The header or the entries past `Options.limits`.
    LimitExceeded,
    Truncated,
    ReadFailed,
    OutOfMemory,
};

pub fn open(gpa: Allocator, source: Source, options: Options) OpenError!Archive {
    var a: Archive = .{ .gpa = gpa, .source = source, .options = options, .arena = .init(gpa) };
    errdefer a.deinit();
    const size = try source.size();
    var start_bytes: [header.start_len]u8 = undefined;
    source.readAt(0, &start_bytes) catch |e| return switch (e) {
        error.Truncated => a.fail(0, .signature, error.Invalid),
        error.ReadFailed => error.ReadFailed,
    };
    const start = header.parseStart(&start_bytes) catch return a.fail(0, .signature, error.Invalid);
    // An empty archive has no header.
    if (start.len == 0) return a;
    const at = std.math.add(u64, header.start_len, start.offset) catch return a.fail(8, .header_field, error.Invalid);
    if (at > size or start.len > size - at) return a.fail(at, .truncated, error.Truncated);
    if (Limits.over(options.limits.directory, start.len)) return a.fail(at, .directory_limit, error.LimitExceeded);
    const bytes = try a.arena.allocator().alloc(u8, @intCast(start.len));
    try source.readAt(at, bytes);
    if (warp.crc32(0, bytes) != start.crc) return a.fail(at, .checksum, error.Corrupt);
    const h = try a.parse(bytes, at);
    a.streams = h.streams;
    a.pack_starts = try a.packStarts(&a.streams, at);
    try a.build(h.files);
    return a;
}

pub fn deinit(a: *Archive) void {
    if (a.cursor) |c| {
        c.close();
        a.gpa.destroy(c);
    }
    a.arena.deinit();
    a.* = undefined;
}

/// The archive's entries, in order.
pub fn entries(a: *const Archive) []const Item {
    return a.items;
}

fn fail(a: *const Archive, at: u64, reason: Diagnostic.Reason, e: anytype) @TypeOf(e) {
    Diagnostic.set(a.options.diagnostic, 0, at, reason);
    return e;
}

/// The header, through as many encodings as wrap it.
fn parse(a: *Archive, first: []const u8, at: u64) OpenError!header.Header {
    var bytes = first;
    var rounds: u8 = 0;
    while (true) : (rounds += 1) {
        var p: header.Parser = .{ .arena = a.arena.allocator(), .bytes = bytes, .limits = a.options.limits };
        const kind = p.number() catch return a.fail(at, .directory, error.Invalid);
        if (kind == header.id.header) return p.header() catch |e| a.headerError(e, at + p.at);
        if (kind != header.id.encoded_header or rounds == max_encodings) return a.fail(at, .directory, error.Invalid);
        var s = p.streams() catch |e| return a.headerError(e, at + p.at);
        bytes = try a.decodeHeader(&s, at);
    }
}

fn headerError(a: *const Archive, e: header.Error, at: u64) OpenError {
    return switch (e) {
        error.Invalid => a.fail(at, .directory, error.Invalid),
        error.Unsupported => a.fail(at, .unsupported_feature, error.Unsupported),
        error.LimitExceeded => a.fail(at, .entries_limit, error.LimitExceeded),
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Each packed stream's offset; all of them end before the header at
/// `end`.
fn packStarts(a: *Archive, s: *const header.Streams, end: u64) OpenError![]const u64 {
    const starts = try a.arena.allocator().alloc(u64, s.pack_sizes.len);
    var pos = std.math.add(u64, header.start_len, s.pack_pos) catch return a.fail(0, .header_field, error.Invalid);
    for (s.pack_sizes, starts) |n, *st| {
        st.* = pos;
        pos = std.math.add(u64, pos, n) catch return a.fail(0, .header_field, error.Invalid);
    }
    if (pos > end) return a.fail(end, .header_field, error.Invalid);
    return starts;
}

/// An encoded header: the one folder of `s`, decoded whole and checked.
fn decodeHeader(a: *Archive, s: *const header.Streams, at: u64) OpenError![]const u8 {
    if (s.folders.len != 1) return a.fail(at, .directory, error.Invalid);
    const starts = try a.packStarts(s, at);
    const f = &s.folders[0];
    const size = f.size();
    if (Limits.over(a.options.limits.directory, size)) return a.fail(at, .directory_limit, error.LimitExceeded);
    const out = try a.arena.allocator().alloc(u8, @intCast(size));
    const c = try a.gpa.create(Cursor);
    defer a.gpa.destroy(c);
    c.open(a, s, starts, 0) catch |e| return a.openError(e, at);
    defer c.close();
    var whole: Checked = .init(c.out, size, f.crc, &.{});
    var w: Io.Writer = .fixed(out);
    _ = whole.interface.streamRemaining(&w) catch |e| switch (e) {
        error.WriteFailed => unreachable, // unreachable: the buffer is the declared size, and `whole` gives no more
        error.ReadFailed => return switch (c.failure(&whole)) {
            error.Truncated => a.fail(at, .truncated, error.Truncated),
            error.WrongPassword => a.fail(at, .authentication, error.WrongPassword),
            error.ReadFailed => error.ReadFailed,
            else => a.fail(at, .codec, error.Corrupt),
        },
    };
    return out;
}

fn openError(a: *const Archive, e: Cursor.FolderError, at: u64) OpenError {
    return switch (e) {
        error.UnsupportedMethod => blk: {
            if (a.options.diagnostic) |d| d.* = .{ .offset = at, .reason = .unsupported_method, .method = a.refused };
            break :blk error.UnsupportedMethod;
        },
        error.UnsupportedEncryption => a.fail(at, .unsupported_encryption, error.UnsupportedEncryption),
        error.PasswordRequired => a.fail(at, .password_required, error.PasswordRequired),
        error.Invalid => a.fail(at, .header_field, error.Invalid),
        error.LimitExceeded => a.fail(at, .window_limit, error.LimitExceeded),
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

// ---------------------------------------------------------------------
// Entries

/// The items: each file's entry, and its substream in order of the
/// folders that have any.
fn build(a: *Archive, files: []const header.File) OpenError!void {
    const arena = a.arena.allocator();
    const items = try arena.alloc(Item, files.len);
    const folders = a.streams.folders;
    var folder: u32 = 0;
    var in_folder: u32 = 0;
    for (files, items, 0..) |f, *it, i| {
        it.* = .{ .entry = .{ .name = "" }, .index = @intCast(i), .attributes = f.attributes, .anti = f.anti };
        if (f.stream) {
            if (in_folder == 0) {
                while (folder < folders.len and folders[folder].streams == 0) folder += 1;
                if (folder == folders.len) return a.fail(0, .directory, error.Invalid);
            }
            const fo = &folders[folder];
            it.folder = folder;
            it.stream = in_folder;
            it.entry.size = a.streams.stream_sizes[fo.first_stream + in_folder];
            it.crc = a.streams.stream_crcs[fo.first_stream + in_folder];
            it.encrypted = encrypted(fo);
            in_folder += 1;
            if (in_folder == fo.streams) {
                folder += 1;
                in_folder = 0;
            }
        }
        try describe(arena, f, &it.entry);
    }
    a.items = items;
}

fn encrypted(f: *const header.Folder) bool {
    for (f.coders) |c| if (c.id == coder.aes256) return true;
    return false;
}

const unix_extension = 0x8000;
const attribute_directory = 0x10;
const attribute_readonly = 0x01;

/// The entry's kind, mode, name and times, as libarchive reads them.
fn describe(arena: Allocator, f: header.File, e: *Entry) Allocator.Error!void {
    const attr = f.attributes orelse 0;
    // A Unix mode in the high bits, or the permissions Windows
    // attributes imply.
    var mode: u32 = if (attr & unix_extension != 0) attr >> 16 else if (attr & attribute_directory != 0) 0o040755 else 0o100644;
    // No stream and not an empty file: a directory, whatever its mode says.
    const dir = !f.stream and !f.empty_file;
    if (mode == 0) {
        mode = if (dir) 0o040777 else 0o100666;
    } else if (dir and mode & 0o170000 != 0o040000) mode = (mode & 0o7777) | 0o040000;
    if (attr & attribute_readonly != 0) mode &= ~@as(u32, 0o222);
    e.kind = switch (mode & 0o170000) {
        0o040000 => .directory,
        0o120000 => if (e.size == 0) .file else .symlink,
        0o020000 => .character_device,
        0o060000 => .block_device,
        0o010000 => .fifo,
        0o140000 => .other,
        else => .file,
    };
    e.mode = mode & 0o7777;
    e.mtime = filetime(f.mtime);
    e.atime = filetime(f.atime);
    e.btime = filetime(f.ctime);
    try name(arena, f.name, e);
}

/// FILETIME, 100 ns since 1601, as a timestamp.
fn filetime(t: ?u64) ?Io.Timestamp {
    return time.fromFiletime(t orelse return null);
}

/// The name as UTF-8 from UTF-16LE; an unpaired surrogate is kept as
/// WTF-8, and the name is then `unspecified`. A directory's ends in `/`.
fn name(arena: Allocator, utf16: []const u8, e: *Entry) Allocator.Error!void {
    const units = try arena.alloc(u16, utf16.len / 2);
    for (units, 0..) |*u, i| u.* = std.mem.readInt(u16, utf16[2 * i ..][0..2], .little);
    const len = std.unicode.calcWtf8Len(units);
    const slash = e.kind == .directory and (units.len == 0 or units[units.len - 1] != '/');
    const out = try arena.alloc(u8, len + @intFromBool(slash));
    _ = std.unicode.wtf16LeToWtf8(out, units);
    if (slash) out[len] = '/';
    e.name = out;
    e.encoding = if (text.validUtf8(out)) .utf8 else .unspecified;
}

// ---------------------------------------------------------------------
// Contents

pub const ContentsError = error{
    /// The folder's coders break the format, or its packed stream lies
    /// outside the archive.
    Invalid,
    /// A coder warp has no decoder for yet, or one hold does not read
    /// (PPMd, BCJ2, coders with several streams).
    UnsupportedMethod,
    /// More key rounds than 7-Zip allows, or a password past its bound.
    UnsupportedEncryption,
    PasswordRequired,
    /// A codec's header asks for more history than `Limits.window`.
    LimitExceeded,
    /// An earlier entry of the folder, decoded to reach this one, failed:
    /// `err()` says how.
    Corrupt,
    Truncated,
    ReadFailed,
    OutOfMemory,
};

/// What was wrong with an entry, behind its reader's `ReadFailed`.
pub const Error = Checked.Error || Bounded.Error || aes.Error || codec.Decoder.Failure || error{
    /// An encrypted folder's stream fails: the password is wrong, or the
    /// stream is corrupt. 7z's AES carries no MAC to tell the two apart.
    WrongPassword,
};

/// `Error`, or `ReadFailed` for the archive's input.
const Failure = Error || error{ReadFailed};

/// `item`'s contents: exactly its size, its CRC checked at the end, and
/// the folder's own at its last entry. Valid until the next call or
/// `deinit`. `buffer` holds the contents' reads.
pub fn contents(a: *Archive, item: Item, buffer: []u8) ContentsError!*Io.Reader {
    const folder = item.folder orelse {
        a.empty = .fixed("");
        return &a.empty;
    };
    const c = a.cursor orelse blk: {
        const c = try a.gpa.create(Cursor);
        c.* = .{};
        a.cursor = c;
        break :blk c;
    };
    if (!c.ready(folder, item.stream)) {
        c.close();
        c.open(a, &a.streams, a.pack_starts, folder) catch |e| return a.contentsOpenError(e, item);
    }
    const f = &a.streams.folders[folder];
    c.skipTo(&a.streams, f, item.stream) catch return a.failEntry(item, .codec, error.Corrupt);
    const last = item.stream + 1 == f.streams;
    c.entry = if (last) .init(c.out, item.entry.size, item.crc, buffer) else .initPart(c.out, item.entry.size, item.crc, buffer);
    c.entry_open = true;
    c.next = item.stream + 1;
    return &c.entry.interface;
}

/// What was wrong with the last entry's contents, behind its reader's
/// `ReadFailed`; null when it was the archive's input.
pub fn err(a: *const Archive) ?Error {
    const c = a.cursor orelse return null;
    if (!c.entry_open) return null;
    return switch (c.failure(&c.entry)) {
        error.ReadFailed => null,
        else => |e| e,
    };
}

fn failEntry(a: *const Archive, item: Item, reason: Diagnostic.Reason, e: anytype) @TypeOf(e) {
    Diagnostic.set(a.options.diagnostic, item.index, 0, reason);
    return e;
}

fn contentsOpenError(a: *Archive, e: Cursor.FolderError, item: Item) ContentsError {
    return switch (e) {
        error.UnsupportedMethod => blk: {
            if (a.options.diagnostic) |d| d.* = .{ .entry = item.index, .reason = .unsupported_method, .method = a.refused };
            break :blk error.UnsupportedMethod;
        },
        error.UnsupportedEncryption => a.failEntry(item, .unsupported_encryption, error.UnsupportedEncryption),
        error.PasswordRequired => a.failEntry(item, .password_required, error.PasswordRequired),
        error.Invalid => a.failEntry(item, .header_field, error.Invalid),
        error.LimitExceeded => a.failEntry(item, .window_limit, error.LimitExceeded),
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// A folder's decoders, from its packed streams to its output, and the
/// entry being read from it. A coder's in-stream is another's output or a
/// packed stream; each packed stream is read by a reader of its own, so
/// BCJ2's four are read side by side.
const Cursor = struct {
    folder: ?u32 = null,
    /// The next substream the output is at.
    next: u32 = 0,
    packs: [max_packs]Pack = undefined,
    packs_len: u8 = 0,
    stages: [max_chain]Stage = undefined,
    len: u8 = 0,
    /// The folder's output: the last stage's checked reader.
    out: *Io.Reader = undefined,
    entry: Checked = undefined,
    entry_open: bool = false,
    key: aegis.Secret([32]u8) = .init(@splat(0)),
    encrypted: bool = false,

    const Pack = struct {
        view: Source.View,
        file_buffer: [4096]u8,
        bounded: Bounded,
        buffer: [16 * 1024]u8,
    };

    const Stage = struct {
        decoder: union(enum) { codec: codec.Decoder, aes: aes.Reader, bcj2: warp.Bcj2 },
        checked: Checked,
        buffer: [16 * 1024]u8,
        /// BCJ2's own buffering.
        staging: [4096]u8,

        fn reader(s: *Stage) *Io.Reader {
            return switch (s.decoder) {
                .codec => |*d| d.reader(),
                .aes => |*r| &r.interface,
                .bcj2 => |*r| &r.interface,
            };
        }
    };

    /// A stream a coder reads, and its length.
    const Input = struct { reader: *Io.Reader, len: u64 };

    const FolderError = error{ Invalid, UnsupportedMethod, UnsupportedEncryption, PasswordRequired, LimitExceeded, ReadFailed, OutOfMemory };

    /// Whether the output is at or before substream `k` of `folder`, and
    /// nothing in the folder failed.
    fn ready(c: *Cursor, folder: u32, k: u32) bool {
        if (c.folder != folder or c.next > k) return false;
        return c.failure(if (c.entry_open) &c.entry else null) == error.ReadFailed;
    }

    /// The decoders of folder `index` of `s`, its packed streams at
    /// `starts`.
    fn open(c: *Cursor, a: *Archive, s: *const header.Streams, starts: []const u64, index: u32) FolderError!void {
        c.* = .{};
        const f = &s.folders[index];
        if (f.packed_ins.len > max_packs) return error.Invalid;
        for (f.coders) |cd| if (cd.outs != 1 or (cd.ins != 1 and cd.id != coder.bcj2)) {
            a.refused = cd.id;
            return error.UnsupportedMethod;
        };
        for (f.coders) |cd| if (cd.id == coder.bcj2 and cd.ins != 4) return error.Invalid;
        errdefer c.close();
        const main = f.mainOut();
        const top = try c.output(a, s, starts, f, main, 0);
        c.out = top.reader;
        c.folder = index;
    }

    /// Out-stream `o` of `f`: its coder's decoder over the streams it
    /// reads, checked against its size (and the folder's CRC at its
    /// output). Every coder has one out-stream, so `o` is its coder's.
    fn output(c: *Cursor, a: *Archive, s: *const header.Streams, starts: []const u64, f: *const header.Folder, o: u32, depth: u8) FolderError!Input {
        // A folder whose binds go round in a circle is not one.
        if (depth == max_chain or o >= f.coders.len) return error.Invalid;
        const cd = f.coders[o];
        var first_in: u32 = 0;
        for (f.coders[0..o]) |before| first_in += before.ins;
        var ins: [4]Input = undefined;
        for (ins[0..cd.ins], 0..) |*in, k| in.* = try c.input(a, s, starts, f, first_in + @as(u32, @intCast(k)), depth);
        if (c.len == max_chain) return error.Invalid;
        const st = &c.stages[c.len];
        if (cd.id == coder.bcj2) {
            st.decoder = .{ .bcj2 = .init(.{ .main = ins[0].reader, .call = ins[1].reader, .jump = ins[2].reader, .range = ins[3].reader }, &st.staging, f.sizes[o]) };
        } else try c.stage(a, st, cd, ins[0].reader, ins[0].len, f.sizes[o]);
        c.len += 1;
        const expected = if (o == f.mainOut()) f.crc else null;
        st.checked = .init(st.reader(), f.sizes[o], expected, &st.buffer);
        return .{ .reader = &st.checked.interface, .len = f.sizes[o] };
    }

    /// In-stream `i` of `f`: the out-stream bound to it, or its packed
    /// stream, read by a reader of its own.
    fn input(c: *Cursor, a: *Archive, s: *const header.Streams, starts: []const u64, f: *const header.Folder, i: u32, depth: u8) FolderError!Input {
        for (f.binds) |b| if (b.in == i) return c.output(a, s, starts, f, b.out, depth + 1);
        const p = for (f.packed_ins, 0..) |in, p| {
            if (in == i) break p;
        } else return error.Invalid;
        if (c.packs_len == max_packs) return error.Invalid;
        const n = s.pack_sizes[f.first_pack + p];
        const pack = &c.packs[c.packs_len];
        const at = a.source.independentAt(starts[f.first_pack + p], &pack.view, &pack.file_buffer) catch return error.ReadFailed;
        pack.bounded = .init(at, n, &pack.buffer);
        c.packs_len += 1;
        return .{ .reader = &pack.bounded.interface, .len = n };
    }

    /// Coder `cd` reading `in_len` bytes from `in`, giving `out_len`.
    fn stage(c: *Cursor, a: *Archive, st: *Stage, cd: header.Coder, in: *Io.Reader, in_len: u64, out_len: u64) FolderError!void {
        if (cd.id == coder.aes256) {
            const password = a.options.password orelse return error.PasswordRequired;
            const props = try aes.parseProps(cd.props);
            try aes.deriveKey(props, password, &c.key);
            c.encrypted = true;
            st.decoder = .{ .aes = undefined };
            st.decoder.aes.init(in, in_len, out_len, props, &c.key) catch return error.Invalid;
            return;
        }
        const decoded = codecOf(cd) catch |e| {
            if (e == error.UnsupportedMethod) a.refused = cd.id;
            return e;
        };
        st.decoder = .{ .codec = undefined };
        st.decoder.codec.init(a.gpa, decoded, in, .{ .limits = a.options.limits, .size = out_len }) catch |e| return switch (e) {
            error.UnsupportedMethod => {
                a.refused = cd.id;
                return error.UnsupportedMethod;
            },
            error.Invalid => error.Invalid,
            error.LimitExceeded => error.LimitExceeded,
            error.ReadFailed => error.ReadFailed,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    /// The decoder of coder `cd`, from its id and properties as 7-Zip
    /// writes them.
    fn codecOf(cd: header.Coder) error{ Invalid, UnsupportedMethod }!codec.Coder {
        const bcj: warp.xz.Bcj = switch (cd.id) {
            coder.copy => return .{ .method = .stored },
            coder.deflate => return .{ .method = .deflate },
            coder.deflate64 => return .{ .method = .deflate64 },
            coder.bzip2 => return .{ .method = .bzip2 },
            coder.zstd => return .{ .method = .zstd },
            coder.lzma => {
                // lc, lp and pb in a byte, then the dictionary.
                if (cd.props.len < 5) return error.Invalid;
                const properties = warp.lzma.Properties.parse(cd.props[0]) orelse return error.Invalid;
                return .{ .lzma = .{ .properties = properties, .dictionary = std.mem.readInt(u32, cd.props[1..5], .little) } };
            },
            coder.lzma2 => {
                if (cd.props.len != 1) return error.Invalid;
                return .{ .lzma2 = .{ .dictionary = lzma2Dictionary(cd.props[0]) orelse return error.Invalid } };
            },
            coder.delta => {
                // The distance less one.
                if (cd.props.len != 1) return error.Invalid;
                return .{ .filter = .{ .delta = @as(u16, cd.props[0]) + 1 } };
            },
            coder.x86 => .x86,
            coder.powerpc => .powerpc,
            coder.ia64 => .ia64,
            coder.arm => .arm,
            coder.armthumb => .armthumb,
            coder.sparc => .sparc,
            coder.arm64 => .arm64,
            coder.riscv => .riscv,
            else => return error.UnsupportedMethod,
        };
        // A branch converter: no properties, or where it starts.
        const start: u32 = switch (cd.props.len) {
            0 => 0,
            4 => std.mem.readInt(u32, cd.props[0..4], .little),
            else => return error.Invalid,
        };
        if (start % bcj.alignment() != 0) return error.Invalid;
        return .{ .filter = .{ .bcj = .{ .kind = bcj, .start = start } } };
    }

    /// The dictionary an LZMA2 properties byte names: 2 or 3 times a power
    /// of two from 4 KiB, 40 for 4 GiB less one; null past 40.
    fn lzma2Dictionary(byte: u8) ?u32 {
        if (byte > 40) return null;
        if (byte == 40) return std.math.maxInt(u32);
        return @as(u32, 2 | (byte & 1)) << @intCast(byte / 2 + 11);
    }

    /// Moves the output to substream `k` of `f`: the rest of the entry
    /// being read, then the substreams before `k`, discarded.
    fn skipTo(c: *Cursor, s: *const header.Streams, f: *const header.Folder, k: u32) Io.Reader.Error!void {
        if (c.entry_open) {
            c.entry_open = false;
            try c.out.discardAll64(c.entry.left);
        }
        while (c.next < k) : (c.next += 1) try c.out.discardAll64(s.stream_sizes[f.first_stream + c.next]);
    }

    /// What failed behind a `ReadFailed` of `top`, a reader over `out`;
    /// `ReadFailed` when nothing of the folder did.
    fn failure(c: *const Cursor, top: ?*const Checked) Failure {
        for (c.packs[0..c.packs_len]) |*p| if (p.bounded.failure) |e| return e;
        var i: usize = 0;
        while (i < c.len) : (i += 1) {
            const st = &c.stages[i];
            const own: ?Error = switch (st.decoder) {
                .aes => |*r| r.err(),
                .codec => |*d| d.failure(),
                // A call, jump or range stream short of what the code asks.
                .bcj2 => |*r| if (r.err() != null) @as(Error, error.CorruptStream) else null,
            };
            const bad: ?Error = if (own) |o| o else if (st.checked.failure) |f| f else null;
            if (bad) |e| return if (c.encrypted) error.WrongPassword else e;
        }
        if (top) |t| if (t.failure) |e| return if (c.encrypted) error.WrongPassword else e;
        return error.ReadFailed;
    }

    fn close(c: *Cursor) void {
        var i: usize = 0;
        while (i < c.len) : (i += 1) switch (c.stages[i].decoder) {
            .codec => |*d| d.deinit(),
            .aes => |*r| r.deinit(),
            .bcj2 => {},
        };
        c.len = 0;
        c.packs_len = 0;
        c.folder = null;
        c.key.deinit();
    }
};
