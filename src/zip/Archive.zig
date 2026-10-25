//! Reads a zip archive through its central directory: random access, from
//! a file or from memory. `open` finds the end records (ZIP64's
//! included), holds the directory, checks every record against the
//! archive's bounds and refuses entries whose data overlap (Fifield's
//! non-recursive bomb, 2019). An entry's contents are read through
//! `Contents`, its local header checked against its record, its size and
//! CRC-32 against what the directory declares. One entry's contents are
//! read at a time: a file's position is shared.
const Archive = @This();

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const aegis = @import("aegis");
const format = @import("format.zig");
const aes = @import("aes.zig");
const Record = @import("Record.zig");
const codec = @import("../codec.zig");
const Limits = @import("../Limits.zig");
const Diagnostic = @import("../Diagnostic.zig");
const Bounded = @import("../Bounded.zig");
const Checked = @import("../Checked.zig");
const Entry = @import("../Entry.zig");

/// Where the archive's bytes are.
pub const Source = @import("../source.zig").Source;

pub const Options = struct {
    limits: Limits = .{},
    diagnostic: ?*Diagnostic = null,
};

/// Private: the allocator of the directory.
gpa: Allocator,
source: Source,
options: Options,
/// Private: the central directory's records, whole.
directory: []u8,
/// Private: the records' count.
count: u64,
/// Private: the local headers' offsets in order, and the directory's
/// start after them: where each entry's bytes must end.
bounds: []u64,
/// The archive's comment.
comment: []const u8,
/// Private: the comment's bytes.
comment_buffer: []u8,
/// Bytes before the archive proper (a self-extractor's program), which
/// every offset the archive records is counted from.
base: u64,

pub const OpenError = error{
    /// No end record, or a record or field that breaks the format.
    Invalid,
    /// A split or spanned archive: its parts are not read.
    Unsupported,
    /// Two entries' data overlap, or an entry's reaches into the next.
    Overlap,
    /// The directory or the entries past `Options.limits`.
    LimitExceeded,
    /// The archive ended before a record it declares.
    Truncated,
    ReadFailed,
    OutOfMemory,
};

pub fn open(gpa: Allocator, source: Source, options: Options) OpenError!Archive {
    const size = try source.size();
    var a: Archive = .{
        .gpa = gpa,
        .source = source,
        .options = options,
        .directory = &.{},
        .count = 0,
        .bounds = &.{},
        .comment = "",
        .comment_buffer = &.{},
        .base = 0,
    };
    errdefer a.deinit();
    const end = try a.findEnd(size);
    if (Limits.over(options.limits.directory, end.dir_size)) return a.fail(end.at, .directory_limit, error.LimitExceeded);
    if (Limits.overEntries(options.limits.entries, end.entries)) return a.fail(end.at, .entries_limit, error.LimitExceeded);
    // The directory ends where the end records begin; whatever comes
    // before the offset it records is prepended.
    if (end.dir_size > end.at) return a.fail(end.at, .directory, error.Invalid);
    const dir_start = end.at - end.dir_size;
    if (dir_start < end.dir_offset) return a.fail(end.at, .directory, error.Invalid);
    a.base = dir_start - end.dir_offset;
    if (end.entries > end.dir_size / format.central_len) return a.fail(end.at, .directory, error.Invalid);
    a.directory = try gpa.alloc(u8, @intCast(end.dir_size));
    try a.readAt(dir_start, a.directory);
    try a.check(end, dir_start);
    return a;
}

pub fn deinit(a: *Archive) void {
    a.gpa.free(a.directory);
    a.gpa.free(a.bounds);
    a.gpa.free(a.comment_buffer);
    a.* = undefined;
}

/// Entries in the archive.
pub fn len(a: *const Archive) u64 {
    return a.count;
}

/// The sum of the entries' declared sizes: what extracting them all
/// writes, known before anything is written.
pub fn declared(a: *const Archive) u64 {
    var total: u64 = 0;
    var it = a.iterate();
    while (it.next()) |r| total +|= r.entry.size;
    return total;
}

/// The entries, in the directory's order.
pub fn iterate(a: *const Archive) Iterator {
    return .{ .archive = a };
}

pub const Iterator = struct {
    archive: *const Archive,
    at: usize = 0,

    /// The next record; every record was checked by `open`.
    pub fn next(it: *Iterator) ?Record {
        if (it.at == it.archive.directory.len) return null;
        const r = parseRecord(it.archive.directory, &it.at, it.archive.base) catch unreachable; // unreachable: checked by open
        return r;
    }
};

/// The first entry named `name`, as the archive spells it.
pub fn find(a: *const Archive, name: []const u8) ?Record {
    var it = a.iterate();
    while (it.next()) |r| if (std.mem.eql(u8, r.entry.name, name)) return r;
    return null;
}

//=========================================================================
// Contents

pub const ContentsOptions = struct {
    /// The password of an AES entry.
    password: ?*const aegis.SecretBytes = null,
};

pub const ContentsError = error{
    /// The local header disagrees with the record, or the data reaches
    /// past where the next entry starts.
    Invalid,
    /// The method is one warp has no decoder for yet.
    UnsupportedMethod,
    /// ZipCrypto, PKWARE's strong encryption or AES-192 (design §0).
    UnsupportedEncryption,
    /// An AES entry and no password.
    PasswordRequired,
    WrongPassword,
    /// A codec's header asks for more history than `Limits.window`.
    LimitExceeded,
    Truncated,
    ReadFailed,
    OutOfMemory,
};

/// An entry's contents: initialized in place by `Archive.contents`, read
/// through `reader()`, released by `deinit`.
pub const Contents = struct {
    stored: Bounded,
    stored_buffer: [16 * 1024]u8,
    file_view: Io.Reader,
    decrypt: ?aes.Reader = null,
    decoder: codec.Decoder,
    checked: Checked,

    /// The entry's bytes: exactly its size, its CRC-32 and any AES MAC
    /// checked at the end. An `error.ReadFailed` is the archive's input
    /// or, when `err()` names one, the entry itself.
    pub fn reader(c: *Contents) *Io.Reader {
        return &c.checked.interface;
    }

    pub const Error = Checked.Error || Bounded.Error || aes.Error || error{CorruptStream};

    /// What was wrong with the entry, behind its reader's `ReadFailed`.
    pub fn err(c: *const Contents) ?Error {
        if (c.stored.failure) |e| return e;
        if (c.decrypt) |*d| if (d.failure) |e| return e;
        if (c.decoder.failed()) return error.CorruptStream;
        return c.checked.failure;
    }

    pub fn deinit(c: *Contents) void {
        c.decoder.deinit();
        if (c.decrypt) |*d| d.deinit();
        c.* = undefined;
    }
};

/// Opens `record`'s contents into `c`. `buffer` holds the contents' reads
/// (any length; the buffered reads need it as long as what they ask).
pub fn contents(a: *Archive, c: *Contents, record: Record, buffer: []u8, options: ContentsOptions) ContentsError!void {
    switch (record.encryption) {
        .none, .aes => {},
        .zipcrypto, .strong => return a.failContents(record.offset, .unsupported_encryption, error.UnsupportedEncryption),
    }
    const data = try a.localData(record);
    const input = try a.source.readerAt(data, &c.file_view);
    c.stored = .init(input, record.compressed, &c.stored_buffer);
    var plain: *Io.Reader = &c.stored.interface;
    c.decrypt = null;
    if (record.aes) |info| {
        const password = options.password orelse return a.failContents(record.offset, .password_required, error.PasswordRequired);
        c.decrypt = @as(aes.Reader, undefined);
        c.decrypt.?.init(plain, record.compressed, info.strength, password) catch |e| {
            c.decrypt = null;
            return switch (e) {
                error.UnsupportedEncryption => a.failContents(record.offset, .unsupported_encryption, error.UnsupportedEncryption),
                error.WrongPassword => a.failContents(record.offset, .authentication, error.WrongPassword),
                error.Invalid => a.failContents(record.offset, .header_field, error.Invalid),
                error.Truncated => error.Truncated,
                error.ReadFailed => if (c.stored.failure != null) error.Truncated else error.ReadFailed,
            };
        };
        plain = &c.decrypt.?.interface;
    }
    errdefer if (c.decrypt) |*d| d.deinit();
    c.decoder.init(a.gpa, record.method, plain, .{ .limits = a.options.limits }) catch |e| return switch (e) {
        error.UnsupportedMethod => blk: {
            if (a.options.diagnostic) |d| d.* = .{ .offset = record.offset, .reason = .unsupported_method, .method = @backingInt(record.method) };
            break :blk error.UnsupportedMethod;
        },
        error.LimitExceeded => a.failContents(record.offset, .window_limit, error.LimitExceeded),
        error.Invalid => a.failContents(record.offset, .codec, error.Invalid),
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
    // AE-2 entries carry no CRC: the MAC authenticates them instead.
    const crc: ?u32 = if (record.aes) |info| (if (info.version == 2) null else record.crc) else record.crc;
    c.checked = .init(c.decoder.reader(), record.entry.size, crc, buffer);
}

pub const LocalError = error{
    /// The local header disagrees with the record, or its extra fields
    /// are malformed.
    Invalid,
    LimitExceeded,
    Truncated,
    ReadFailed,
    OutOfMemory,
};

/// `record` with what only its local header holds: Info-ZIP writes an
/// entry's access and change times, and its Unix owner, there and not in
/// the central directory. `extra` receives the local extra fields, which
/// the result's `extra` borrows; the central record decides everything
/// else. Extraction reads every entry through this.
pub fn local(a: *Archive, record: Record, extra: *std.ArrayList(u8)) LocalError!Record {
    var fixed: [format.local_len]u8 = undefined;
    try a.readAt(record.offset, &fixed);
    if (std.mem.readInt(u32, fixed[0..4], .little) != format.local_sig) return a.failContents(record.offset, .local_header_mismatch, error.Invalid);
    const header = format.Local.parse(&fixed);
    if (Limits.over(a.options.limits.header, header.extra_len)) return a.failContents(record.offset, .header_limit, error.LimitExceeded);
    extra.clearRetainingCapacity();
    try extra.resize(a.gpa, header.extra_len);
    try a.readAt(record.offset + format.local_len + header.name_len, extra.items);
    var it: format.ExtraIterator = .{ .bytes = extra.items };
    while (it.next() catch return a.failContents(record.offset, .extra_field, error.Invalid)) |_| {}
    var r = record;
    if (format.findExtra(extra.items, format.Extra.unix_time) catch unreachable) |data| { // unreachable: checked above
        const t = format.unixTimes(data);
        if (t.mtime) |s| r.entry.mtime = Entry.seconds(s);
        if (t.atime) |s| r.entry.atime = Entry.seconds(s);
        if (t.ctime) |s| r.entry.ctime = Entry.seconds(s);
    }
    if (format.findExtra(extra.items, format.Extra.unix_old) catch unreachable) |data| { // unreachable: checked above
        if (format.unixOld(data)) |u| {
            if (u.uid) |id| r.entry.uid = id;
            if (u.gid) |id| r.entry.gid = id;
        }
    }
    if (format.findExtra(extra.items, format.Extra.unix_ids) catch unreachable) |data| { // unreachable: checked above
        if (format.unixIds(data)) |ids| {
            r.entry.uid = ids.uid;
            r.entry.gid = ids.gid;
        }
    }
    return r;
}

/// Where `record`'s stored bytes start, after its local header is checked
/// against it: the same method, and data that ends before the next
/// entry's header.
fn localData(a: *Archive, record: Record) ContentsError!u64 {
    var fixed: [format.local_len]u8 = undefined;
    a.readAt(record.offset, &fixed) catch |e| return switch (e) {
        error.Truncated => error.Truncated,
        error.ReadFailed => error.ReadFailed,
    };
    if (std.mem.readInt(u32, fixed[0..4], .little) != format.local_sig) return a.failContents(record.offset, .local_header_mismatch, error.Invalid);
    const head = format.Local.parse(&fixed);
    if (head.method != @backingInt(record.method) and !(record.aes != null and head.method == @backingInt(codec.Method.aes)))
        return a.failContents(record.offset, .local_header_mismatch, error.Invalid);
    // The name is the central record's to say: a writer may store another
    // spelling in the local header (an ASCII stand-in for a name in its
    // Unicode field, libarchive's zip_7075 corpus), and this reader never
    // takes the local one.
    const at = record.offset + format.local_len + head.name_len;
    const data = at + head.extra_len;
    const next = a.boundAfter(record.offset);
    if (data > next or record.compressed > next - data) return a.failContents(record.offset, .overlap, error.Invalid);
    return data;
}

/// Where the entry whose header is at `offset` must end: the next
/// header's offset, or the directory's start.
fn boundAfter(a: *const Archive, offset: u64) u64 {
    var lo: usize = 0;
    var hi: usize = a.bounds.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (a.bounds[mid] <= offset) lo = mid + 1 else hi = mid;
    }
    return a.bounds[@min(lo, a.bounds.len - 1)];
}

//=========================================================================
// Opening

const End = struct {
    /// Where the end records start: ZIP64's record if there is one, else
    /// the end record.
    at: u64,
    entries: u64,
    dir_size: u64,
    dir_offset: u64,
};

fn fail(a: *const Archive, at: u64, reason: Diagnostic.Reason, e: anytype) @TypeOf(e) {
    Diagnostic.set(a.options.diagnostic, 0, at, reason);
    return e;
}

fn failContents(a: *const Archive, at: u64, reason: Diagnostic.Reason, e: anytype) @TypeOf(e) {
    Diagnostic.set(a.options.diagnostic, 0, at, reason);
    return e;
}

fn readAt(a: *Archive, offset: u64, out: []u8) Source.Error!void {
    return a.source.readAt(offset, out);
}

/// The end record: the last signature in the archive's last 64 KiB and 22
/// bytes whose comment ends the archive, and ZIP64's records before it
/// when they are there.
fn findEnd(a: *Archive, size: u64) OpenError!End {
    if (size < format.end_len) return a.fail(0, .trailer, error.Invalid);
    const tail_len: usize = @intCast(@min(size, 0xffff + format.end_len));
    const tail = try a.gpa.alloc(u8, tail_len);
    defer a.gpa.free(tail);
    const tail_at = size - tail_len;
    try a.readAt(tail_at, tail);
    var i = tail_len - format.end_len + 1;
    const found = while (i > 0) {
        i -= 1;
        if (std.mem.readInt(u32, tail[i..][0..4], .little) != format.end_sig) continue;
        const comment_len = std.mem.readInt(u16, tail[i + 20 ..][0..2], .little);
        if (i + format.end_len + comment_len <= tail_len) break i;
    } else return a.fail(size, .trailer, error.Invalid);
    const end = format.End.parse(tail[found..][0..format.end_len]);
    a.comment_buffer = try a.gpa.dupe(u8, tail[found + format.end_len ..][0..end.comment_len]);
    a.comment = a.comment_buffer;
    const end_at = tail_at + found;
    var result: End = .{ .at = end_at, .entries = end.entries, .dir_size = end.dir_size, .dir_offset = end.dir_offset };
    // ZIP64: a locator just before the end record points at its own end
    // record, whose values replace the 16- and 32-bit ones.
    if (end_at >= format.locator64_len) {
        var loc: [format.locator64_len]u8 = undefined;
        try a.readAt(end_at - format.locator64_len, &loc);
        if (std.mem.readInt(u32, loc[0..4], .little) == format.locator64_sig) {
            const disks = std.mem.readInt(u32, loc[16..20], .little);
            if (std.mem.readInt(u32, loc[4..8], .little) != 0 or disks > 1) return a.fail(end_at, .zip64, error.Unsupported);
            // The ZIP64 end record sits right before the locator, whatever
            // offset the locator records (it is off by any prepended bytes).
            const at64 = end_at - format.locator64_len -| format.end64_len;
            var rec: [format.end64_len]u8 = undefined;
            try a.readAt(at64, &rec);
            if (std.mem.readInt(u32, rec[0..4], .little) != format.end64_sig) return a.fail(at64, .zip64, error.Invalid);
            const e64 = format.End64.parse(&rec);
            if (e64.disk != 0 or e64.dir_disk != 0) return a.fail(at64, .zip64, error.Unsupported);
            result = .{ .at = at64, .entries = e64.entries, .dir_size = e64.dir_size, .dir_offset = e64.dir_offset };
            return result;
        }
    }
    // Without ZIP64's records the end record's own disk fields decide; with
    // them, they may all read 0xffff.
    if (end.disk != 0 or end.dir_disk != 0 or end.disk_entries != end.entries) return a.fail(end_at, .trailer, error.Unsupported);
    return result;
}

/// Every record whole and inside the directory, its extra fields well
/// formed, the count the end record declares, and no two entries' data
/// overlapping.
fn check(a: *Archive, end: End, dir_start: u64) OpenError!void {
    var at: usize = 0;
    var count: u64 = 0;
    var offsets: std.ArrayList(u64) = .empty;
    defer offsets.deinit(a.gpa);
    try offsets.ensureTotalCapacity(a.gpa, @intCast(end.entries));
    var lows: std.ArrayList(Low) = .empty;
    defer lows.deinit(a.gpa);
    try lows.ensureTotalCapacity(a.gpa, @intCast(end.entries));
    while (at < a.directory.len) {
        const record_at = dir_start + at;
        const r = parseRecord(a.directory, &at, a.base) catch return a.fail(record_at, .directory, error.Invalid);
        count += 1;
        if (Limits.overEntries(a.options.limits.entries, count)) return a.fail(record_at, .entries_limit, error.LimitExceeded);
        if (r.offset >= dir_start) return a.fail(record_at, .directory, error.Invalid);
        try offsets.append(a.gpa, r.offset);
        // The least an entry occupies: its local header with the name its
        // record gives, and its stored bytes.
        try lows.append(a.gpa, .{ .offset = r.offset, .end = r.offset +| format.local_len +| r.raw_name.len +| r.compressed });
    }
    // A count past 65,535 wraps in a writer that knows no ZIP64.
    if (count != end.entries and !(end.entries < 0xffff and count % 0x10000 == end.entries))
        return a.fail(dir_start, .directory, error.Invalid);
    a.count = count;
    std.mem.sortUnstable(Low, lows.items, {}, Low.less);
    for (lows.items, 0..) |low, i| {
        const next = if (i + 1 < lows.items.len) lows.items[i + 1].offset else dir_start;
        if (low.end > next) return a.fail(low.offset, .overlap, error.Overlap);
    }
    std.mem.sortUnstable(u64, offsets.items, {}, std.sort.asc(u64));
    try offsets.append(a.gpa, dir_start);
    a.bounds = try offsets.toOwnedSlice(a.gpa);
}

const Low = struct {
    offset: u64,
    end: u64,
    fn less(_: void, x: Low, y: Low) bool {
        return x.offset < y.offset;
    }
};

const RecordError = error{Invalid};

/// The record at `at` in the directory, `at` moved past it.
fn parseRecord(dir: []const u8, at: *usize, base: u64) RecordError!Record {
    if (dir.len - at.* < format.central_len) return error.Invalid;
    const fixed = dir[at.*..][0..format.central_len];
    if (std.mem.readInt(u32, fixed[0..4], .little) != format.central_sig) return error.Invalid;
    const c = format.Central.parse(fixed);
    const var_len = @as(usize, c.name_len) + c.extra_len + c.comment_len;
    if (dir.len - at.* - format.central_len < var_len) return error.Invalid;
    var f: format.Fields = .{ .bytes = dir, .at = at.* + format.central_len };
    const name = f.take(c.name_len);
    const extra = f.take(c.extra_len);
    const comment = f.take(c.comment_len);
    at.* = f.at;
    if (c.disk != 0 and c.disk != 0xffff) return error.Invalid;
    var z: format.Zip64 = .{};
    const wide = c.size == 0xffffffff or c.compressed == 0xffffffff or c.offset == 0xffffffff;
    if (wide) {
        const data = (format.findExtra(extra, format.Extra.zip64) catch return error.Invalid) orelse return error.Invalid;
        z = format.Zip64.parse(data, c.size == 0xffffffff, c.compressed == 0xffffffff, c.offset == 0xffffffff) catch return error.Invalid;
    }
    // Every extra field must be whole, which `describe` relies on.
    var it: format.ExtraIterator = .{ .bytes = extra };
    while (it.next() catch return error.Invalid) |_| {}
    var r: Record = .{
        .entry = .{ .name = name, .size = z.size orelse c.size },
        .method = @fromBackingInt(@intCast(c.method)),
        .flags = c.flags,
        .crc = c.crc,
        .compressed = z.compressed orelse c.compressed,
        .offset = std.math.add(u64, z.offset orelse c.offset, base) catch return error.Invalid,
        .made_by = c.made_by,
        .needed = c.needed,
        .internal = c.internal,
        .external = c.external,
        .dos_date = c.dos_date,
        .dos_time = c.dos_time,
        .raw_name = name,
        .extra = extra,
        .comment = comment,
    };
    r.describe();
    return r;
}
