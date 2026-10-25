//! Writes a zip archive to any `std.Io.Writer`: an entry's local header,
//! its contents compressed through warp, a data descriptor when the header
//! could not know its sizes, and at `finish` the central directory and the
//! end records, ZIP64's where a count or an offset needs them.
//!
//! The values the format defines (CRC-32, sizes, offsets, the ZIP64
//! records) are the writer's. The values it leaves to the writer can be
//! set (`Header`): versions, attributes, raw extra fields, the DOS time,
//! when ZIP64 is used, so a caller can reproduce another writer's bytes
//! exactly (git's, for one).
const Writer = @This();

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const warp = @import("warp");
const format = @import("format.zig");
const codec = @import("../codec.zig");
const Entry = @import("../Entry.zig");
const text = @import("../text.zig");

pub const Method = codec.Method;

pub const Options = struct {
    /// The "version made by" every entry gets unless its header names
    /// one: Unix (3), APPNOTE 6.3.
    made_by: u16 = (3 << 8) | 63,
};

/// When an entry's sizes and offset take ZIP64's extra field.
pub const Zip64 = enum {
    /// Where a value does not fit 32 bits; for contents of unknown size,
    /// in the data descriptor only.
    auto,
    /// Always in the local header (sizes written as known, else zero),
    /// as a writer does that may stream past 4 GiB.
    always,
    /// Never: an entry that needs it is refused.
    never,
};

pub const Header = struct {
    entry: Entry,
    method: Method = .deflate,
    /// warp's level for the method; null is its default.
    level: ?i32 = null,
    /// The contents' length, when known before them.
    size: ?u64 = null,
    zip64: Zip64 = .auto,
    /// `add` only: store the contents when compressing makes them no
    /// smaller, as Info-ZIP and git do.
    store_if_larger: bool = false,
    /// A data descriptor after the contents even when the header knows
    /// everything (git's streamed entries).
    descriptor: bool = false,
    made_by: ?u16 = null,
    /// The "version needed to extract"; null computes it from the method,
    /// the kind and ZIP64.
    needed: ?u16 = null,
    internal: u16 = 0,
    /// The external attributes; null makes them from the kind and mode
    /// (a Unix mode in the high 16 bits, the DOS directory bit).
    external: ?u32 = null,
    /// The DOS time; null makes it from `entry.mtime`, in UTC.
    dos: ?Dos = null,
    /// Info-ZIP's extended timestamp (0x5455) with `entry.mtime`.
    extended_time: bool = true,
    /// Extra fields for the local header and the central record, after
    /// the writer's own.
    extra: []const u8 = "",
    /// The central record's extra fields when they differ from the local
    /// header's.
    central_extra: ?[]const u8 = null,
    comment: []const u8 = "",
    /// The UTF-8 flag (bit 11); null sets it for a name that is not ASCII
    /// and is well-formed UTF-8.
    utf8: ?bool = null,
};

pub const Dos = struct { date: u16, time: u16 };

/// What a raw entry declares of the compressed bytes the caller copies.
pub const Raw = struct {
    crc: u32,
    size: u64,
    compressed: u64,
};

/// Private: the allocator of the directory and the encoders.
gpa: Allocator,
/// Private: the archive.
output: *Io.Writer,
options: Options,
/// Private: bytes written.
offset: u64 = 0,
directory: std.ArrayList(u8) = .empty,
count: u64 = 0,
/// Private: the entry being written.
current: ?Current = null,
encoder: codec.Encoder = undefined,
/// Private: the compressed bytes, counted on their way out, and where they
/// are staged (warp's encoders write into a writer's buffer).
counter: Io.Writer,
counter_buffer: [16 * 1024]u8 = undefined,
/// Private: the contents, hashed and counted on their way in.
front: Io.Writer,
failure: ?ContentsError = null,
finished: bool = false,

const Current = struct {
    header: Header,
    method: Method,
    flags: u16,
    needed: u16,
    local_offset: u64,
    local_zip64: bool,
    descriptor: bool,
    crc: warp.Crc32 = .init,
    size: u64 = 0,
    compressed: u64 = 0,
    raw: ?Raw = null,
    dos: Dos,
};

pub const ContentsError = error{
    /// More contents than the header's `size`, or than a raw entry's
    /// `compressed`.
    TooLong,
};

pub const BeginError = error{
    /// The previous entry is still open.
    EntryOpen,
    /// A name, comment or extra block past 65,535 bytes, or ZIP64 needed
    /// where the header says `never`.
    TooLarge,
    /// warp has no encoder for the method.
    UnsupportedMethod,
    WriteFailed,
    OutOfMemory,
};

pub const EndError = error{
    /// Fewer contents than the header's `size`, or than a raw entry's
    /// `compressed`.
    TooShort,
    /// More contents than the header's `size`.
    TooLong,
    TooLarge,
    WriteFailed,
    OutOfMemory,
};

pub fn init(gpa: Allocator, output: *Io.Writer, options: Options) Writer {
    return .{
        .gpa = gpa,
        .output = output,
        .options = options,
        .counter = .{ .vtable = &.{ .drain = drainCounter }, .buffer = &.{} },
        .front = .{ .vtable = &.{ .drain = drainFront, .flush = flushFront }, .buffer = &.{} },
    };
}

pub fn deinit(w: *Writer) void {
    if (w.current != null and w.current.?.raw == null) w.encoder.deinit();
    w.directory.deinit(w.gpa);
    w.* = undefined;
}

/// Writes the entry's local header; its contents follow through the
/// writer returned, then `end`. A symbolic link's contents are its target.
pub fn begin(w: *Writer, h: Header) BeginError!*Io.Writer {
    try w.start(h, null, null);
    w.counter.buffer = &w.counter_buffer;
    w.counter.end = 0;
    w.encoder.init(w.gpa, w.current.?.method, &w.counter, .{ .level = h.level, .size = h.size }) catch |e| {
        w.current = null;
        return e;
    };
    return &w.front;
}

/// An entry whose compressed bytes the caller already has (copied from
/// another archive): the header's method names them, `raw` declares them,
/// and they follow through the writer returned, then `end`.
pub fn beginRaw(w: *Writer, h: Header, declared: Raw) BeginError!*Io.Writer {
    try w.start(h, declared, null);
    w.counter.buffer = &w.counter_buffer;
    w.counter.end = 0;
    return &w.counter;
}

/// An entry whose contents are in memory: no data descriptor, and stored
/// instead when `store_if_larger` finds compressing gains nothing.
pub fn add(w: *Writer, h: Header, bytes: []const u8) (BeginError || EndError)!void {
    var header = h;
    const contents = if (h.entry.kind == .symlink and bytes.len == 0) h.entry.link else bytes;
    header.size = contents.len;
    const crc = warp.crc32(0, contents);
    if (header.method == .stored or contents.len == 0 or !kindHasContents(h.entry.kind)) {
        header.method = .stored;
        try w.start(header, null, .{ .crc = crc, .size = contents.len, .compressed = contents.len });
        try w.output.writeAll(contents);
        w.offset += contents.len;
        w.current.?.compressed = contents.len;
        w.current.?.size = contents.len;
        w.current.?.crc = .{ .value = crc };
        return w.close();
    }
    // Compressed into memory first: the local header knows every size.
    var squeezed: Io.Writer.Allocating = .init(w.gpa);
    defer squeezed.deinit();
    var enc: codec.Encoder = undefined;
    try enc.init(w.gpa, header.method, &squeezed.writer, .{ .level = h.level, .size = contents.len });
    defer enc.deinit();
    enc.writer().writeAll(contents) catch return error.OutOfMemory;
    enc.finish() catch return error.OutOfMemory;
    var data: []const u8 = squeezed.written();
    if (h.store_if_larger and data.len >= contents.len) {
        header.method = .stored;
        data = contents;
    }
    try w.start(header, null, .{ .crc = crc, .size = contents.len, .compressed = data.len });
    try w.output.writeAll(data);
    w.offset += data.len;
    w.current.?.compressed = data.len;
    w.current.?.size = contents.len;
    w.current.?.crc = .{ .value = crc };
    return w.close();
}

/// Ends the current entry: its compressed stream, a data descriptor if
/// the header needed one, and its central record.
pub fn end(w: *Writer) EndError!void {
    const cur = &(w.current orelse unreachable); // unreachable: begin opened one
    if (cur.raw == null) {
        w.front.flush() catch return w.failure orelse error.WriteFailed;
        w.encoder.finish() catch return error.WriteFailed;
        w.encoder.deinit();
        w.counter.flush() catch return w.failure orelse error.WriteFailed;
        if (cur.header.size) |n| if (n != cur.size) return error.TooShort;
    } else {
        w.counter.flush() catch return w.failure orelse error.WriteFailed;
        const declared = cur.raw.?;
        if (cur.compressed != declared.compressed) return error.TooShort;
        cur.size = declared.size;
        cur.crc = .{ .value = declared.crc };
    }
    return w.close();
}

/// Writes the central directory and the end records.
pub fn finish(w: *Writer, comment: []const u8) (EndError || error{EntryOpen})!void {
    if (w.current != null) return error.EntryOpen;
    std.debug.assert(!w.finished);
    if (comment.len > 0xffff) return error.TooLarge;
    const dir_offset = w.offset;
    try w.output.writeAll(w.directory.items);
    w.offset += w.directory.items.len;
    const dir_size: u64 = w.directory.items.len;
    if (w.count >= 0xffff or dir_offset >= 0xffffffff or dir_size >= 0xffffffff) {
        var rec: [format.end64_len + format.locator64_len]u8 = undefined;
        var f: Out = .{ .bytes = &rec };
        f.int(u32, format.end64_sig);
        f.int(u64, format.end64_len - 12);
        f.int(u16, w.options.made_by);
        f.int(u16, 45);
        f.int(u32, 0);
        f.int(u32, 0);
        f.int(u64, w.count);
        f.int(u64, w.count);
        f.int(u64, dir_size);
        f.int(u64, dir_offset);
        f.int(u32, format.locator64_sig);
        f.int(u32, 0);
        f.int(u64, w.offset);
        f.int(u32, 1);
        try w.put(&rec);
    }
    var rec: [format.end_len]u8 = undefined;
    var f: Out = .{ .bytes = &rec };
    f.int(u32, format.end_sig);
    f.int(u16, 0);
    f.int(u16, 0);
    f.int(u16, @intCast(@min(w.count, 0xffff)));
    f.int(u16, @intCast(@min(w.count, 0xffff)));
    f.int(u32, @intCast(@min(dir_size, 0xffffffff)));
    f.int(u32, @intCast(@min(dir_offset, 0xffffffff)));
    f.int(u16, @intCast(comment.len));
    try w.put(&rec);
    try w.put(comment);
    w.output.flush() catch return error.WriteFailed;
    w.finished = true;
}

//=========================================================================

/// Little-endian fields written in place.
const Out = struct {
    bytes: []u8,
    at: usize = 0,
    fn int(o: *Out, comptime T: type, v: T) void {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        std.mem.writeInt(T, o.bytes[o.at..][0..n], v, .little);
        o.at += n;
    }
};

fn kindHasContents(kind: Entry.Kind) bool {
    return kind == .file or kind == .symlink;
}

fn put(w: *Writer, bytes: []const u8) error{WriteFailed}!void {
    try w.output.writeAll(bytes);
    w.offset += bytes.len;
}

fn needed(method: Method, kind: Entry.Kind, zip64: bool) u16 {
    var v: u16 = switch (method) {
        .stored => 10,
        .deflate => 20,
        .deflate64 => 21,
        .bzip2 => 46,
        .aes => 51,
        else => 63,
    };
    if (kind == .directory) v = @max(v, 20);
    if (zip64) v = @max(v, 45);
    return v;
}

fn defaultExternal(e: Entry) u32 {
    const kind_bits: u32 = switch (e.kind) {
        .directory => 0o040000,
        .symlink => 0o120000,
        .character_device => 0o020000,
        .block_device => 0o060000,
        .fifo => 0o010000,
        else => 0o100000,
    };
    const mode: u32 = e.mode orelse switch (e.kind) {
        .directory => 0o755,
        .symlink => 0o777,
        else => 0o644,
    };
    return ((kind_bits | (mode & 0o7777)) << 16) | @as(u32, if (e.kind == .directory) 0x10 else 0);
}

/// The local header, with the values known now: `known` when the caller
/// gives the CRC and sizes (in memory, or raw).
fn start(w: *Writer, h: Header, raw_info: ?Raw, known_in: ?Raw) BeginError!void {
    if (w.current != null) return error.EntryOpen;
    std.debug.assert(!w.finished);
    const e = h.entry;
    if (e.name.len > 0xffff or h.comment.len > 0xffff) return error.TooLarge;
    const known = known_in orelse raw_info;
    const method: Method = if (kindHasContents(e.kind)) h.method else .stored;
    const size_known: ?u64 = if (known) |k| k.size else h.size;
    const descriptor = h.descriptor or known == null;
    const big_size = if (size_known) |n| n >= 0xffffffff else false;
    const big_compressed = if (known) |k| k.compressed >= 0xffffffff else false;
    const local_zip64 = switch (h.zip64) {
        .always => true,
        .auto => big_size or big_compressed,
        .never => if (big_size or big_compressed) return error.TooLarge else false,
    };
    var flags: u16 = 0;
    if (descriptor) flags |= format.Flags.descriptor;
    const utf8 = h.utf8 orelse (!text.isAscii(e.name) and text.validUtf8(e.name));
    if (utf8) flags |= format.Flags.utf8;
    const dos = h.dos orelse blk: {
        const d = format.toDos(e.mtime orelse Entry.seconds(0));
        break :blk Dos{ .date = d.date, .time = d.time };
    };
    const need = h.needed orelse needed(method, e.kind, local_zip64);

    var extra_buf: [9 + 20]u8 = undefined;
    var x: Out = .{ .bytes = &extra_buf };
    if (local_zip64) {
        x.int(u16, format.Extra.zip64);
        x.int(u16, 16);
        x.int(u64, size_known orelse 0);
        x.int(u64, if (known) |k| k.compressed else 0);
    }
    if (h.extended_time) if (unixTime(e)) |t| {
        x.int(u16, format.Extra.unix_time);
        x.int(u16, 5);
        x.bytes[x.at] = 1;
        x.at += 1;
        x.int(i32, t);
    };
    const own_extra = extra_buf[0..x.at];
    if (own_extra.len + h.extra.len > 0xffff) return error.TooLarge;

    const local_offset = w.offset;
    var rec: [format.local_len]u8 = undefined;
    var f: Out = .{ .bytes = &rec };
    f.int(u32, format.local_sig);
    f.int(u16, need);
    f.int(u16, flags);
    f.int(u16, @backingInt(method));
    f.int(u16, dos.time);
    f.int(u16, dos.date);
    f.int(u32, if (known) |k| (if (h.descriptor) 0 else k.crc) else 0);
    f.int(u32, if (local_zip64) 0xffffffff else if (known) |k| (if (h.descriptor and method != .stored) 0 else @as(u32, @intCast(k.compressed))) else 0);
    f.int(u32, if (local_zip64) 0xffffffff else if (size_known) |n| @as(u32, @intCast(n)) else 0);
    f.int(u16, @intCast(e.name.len));
    f.int(u16, @intCast(own_extra.len + h.extra.len));
    try w.put(&rec);
    try w.put(e.name);
    try w.put(own_extra);
    try w.put(h.extra);
    w.current = .{
        .header = h,
        .method = method,
        .flags = flags,
        .needed = need,
        .local_offset = local_offset,
        .local_zip64 = local_zip64,
        .descriptor = descriptor,
        .raw = raw_info,
        .dos = dos,
    };
}

fn unixTime(e: Entry) ?i32 {
    const t = e.mtime orelse return null;
    return std.math.cast(i32, @divFloor(t.nanoseconds, std.time.ns_per_s));
}

/// The descriptor if the entry has one, and its central record.
fn close(w: *Writer) EndError!void {
    const cur = w.current.?;
    defer w.current = null;
    const crc = cur.crc.final();
    const zip64_needed = cur.size >= 0xffffffff or cur.compressed >= 0xffffffff;
    if (zip64_needed and cur.header.zip64 == .never) return error.TooLarge;
    if (cur.descriptor) {
        var rec: [24]u8 = undefined;
        var f: Out = .{ .bytes = &rec };
        f.int(u32, format.descriptor_sig);
        f.int(u32, crc);
        if (cur.local_zip64 or zip64_needed) {
            f.int(u64, cur.compressed);
            f.int(u64, cur.size);
        } else {
            f.int(u32, @intCast(cur.compressed));
            f.int(u32, @intCast(cur.size));
        }
        try w.put(rec[0..f.at]);
    }
    try w.central(cur, crc);
}

fn central(w: *Writer, cur: Current, crc: u32) EndError!void {
    const h = cur.header;
    const e = h.entry;
    const big_size = cur.size >= 0xffffffff;
    const big_compressed = cur.compressed >= 0xffffffff;
    const big_offset = cur.local_offset >= 0xffffffff;
    var extra_buf: [4 + 24 + 9]u8 = undefined;
    var x: Out = .{ .bytes = &extra_buf };
    if (big_size or big_compressed or big_offset) {
        x.int(u16, format.Extra.zip64);
        x.int(u16, 8 * (@as(u16, @intFromBool(big_size)) + @intFromBool(big_compressed) + @intFromBool(big_offset)));
        if (big_size) x.int(u64, cur.size);
        if (big_compressed) x.int(u64, cur.compressed);
        if (big_offset) x.int(u64, cur.local_offset);
    }
    if (h.extended_time) if (unixTime(e)) |t| {
        x.int(u16, format.Extra.unix_time);
        x.int(u16, 5);
        x.bytes[x.at] = 1;
        x.at += 1;
        x.int(i32, t);
    };
    const theirs = h.central_extra orelse h.extra;
    const extra_len = x.at + theirs.len;
    if (extra_len > 0xffff) return error.TooLarge;
    const needed_now = if (h.needed == null and (big_size or big_compressed or big_offset)) @max(cur.needed, 45) else cur.needed;
    var rec: [format.central_len]u8 = undefined;
    var f: Out = .{ .bytes = &rec };
    f.int(u32, format.central_sig);
    f.int(u16, h.made_by orelse w.options.made_by);
    f.int(u16, needed_now);
    f.int(u16, cur.flags);
    f.int(u16, @backingInt(cur.method));
    f.int(u16, cur.dos.time);
    f.int(u16, cur.dos.date);
    f.int(u32, crc);
    f.int(u32, if (big_compressed) 0xffffffff else @intCast(cur.compressed));
    f.int(u32, if (big_size) 0xffffffff else @intCast(cur.size));
    f.int(u16, @intCast(e.name.len));
    f.int(u16, @intCast(extra_len));
    f.int(u16, @intCast(h.comment.len));
    f.int(u16, 0);
    f.int(u16, h.internal);
    f.int(u32, h.external orelse defaultExternal(e));
    f.int(u32, if (big_offset) 0xffffffff else @intCast(cur.local_offset));
    try w.directory.appendSlice(w.gpa, &rec);
    try w.directory.appendSlice(w.gpa, e.name);
    try w.directory.appendSlice(w.gpa, extra_buf[0..x.at]);
    try w.directory.appendSlice(w.gpa, theirs);
    try w.directory.appendSlice(w.gpa, h.comment);
    w.count += 1;
}

//=========================================================================
// The two writers an entry's bytes pass through

/// Compressed bytes to the archive, counted.
fn drainCounter(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const w: *Writer = @alignCast(@fieldParentPtr("counter", io_w)); // safe: the vtable is installed only on a Writer's counter
    const cur = &w.current.?;
    try w.counted(cur, io_w.buffered());
    io_w.end = 0;
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try w.counted(cur, bytes);
        n += bytes.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| try w.counted(cur, last);
    return n + last.len * splat;
}

fn counted(w: *Writer, cur: *Current, bytes: []const u8) Io.Writer.Error!void {
    if (cur.raw) |r| if (bytes.len > r.compressed - cur.compressed) {
        w.failure = error.TooLong;
        return error.WriteFailed;
    };
    try w.output.writeAll(bytes);
    w.offset += bytes.len;
    cur.compressed += bytes.len;
}

/// Contents from the caller, hashed and counted, to the encoder.
fn drainFront(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const w: *Writer = @alignCast(@fieldParentPtr("front", io_w)); // safe: the vtable is installed only on a Writer's front
    const cur = &w.current.?;
    const sink = w.encoder.writer();
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try w.hashed(cur, sink, bytes);
        n += bytes.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| try w.hashed(cur, sink, last);
    return n + last.len * splat;
}

fn hashed(w: *Writer, cur: *Current, sink: *Io.Writer, bytes: []const u8) Io.Writer.Error!void {
    if (cur.header.size) |declared| if (bytes.len > declared - cur.size) {
        w.failure = error.TooLong;
        return error.WriteFailed;
    };
    cur.crc.update(bytes);
    cur.size += bytes.len;
    try sink.writeAll(bytes);
}

fn flushFront(io_w: *Io.Writer) Io.Writer.Error!void {
    _ = io_w;
}
