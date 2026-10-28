//! Reads a zip archive forward from any `std.Io.Reader`, by its local
//! headers, for an archive that cannot be seeked (a pipe, a download). An
//! entry whose sizes come after it in a data descriptor is read to its
//! compressed stream's own end, then checked against the descriptor; a
//! stored entry with a descriptor has no end to find and is refused
//! (`error.Unsupported`), as is an encrypted one. Reading stops at the
//! central directory.
//!
//! Prefer `Archive` where the archive can be seeked: the central directory
//! is the archive's authority, and a local header can disagree with it.
const Stream = @This();

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const warp = @import("warp");
const format = @import("format.zig");
const Record = @import("Record.zig");
const codec = @import("../codec.zig");
const Limits = @import("../Limits.zig");
const Diagnostic = @import("../Diagnostic.zig");
const Bounded = @import("../Bounded.zig");

pub const Options = struct {
    limits: Limits = .{},
    diagnostic: ?*Diagnostic = null,
};

/// Private: the allocator of the header buffers and decoders.
gpa: Allocator,
input: *Io.Reader,
options: Options,
/// Private: the current header's name and extra fields.
header: std.ArrayList(u8) = .empty,
entries: u64 = 0,
done: bool = false,
/// Private: the current entry's contents, while one is open.
open: bool = false,
contents_: Contents,

pub const NextError = error{
    /// A header that is no zip header, or a field that breaks the format.
    Invalid,
    /// A stored entry with a data descriptor, an encrypted entry, or a
    /// method warp has no decoder for.
    Unsupported,
    LimitExceeded,
    Truncated,
    ReadFailed,
    OutOfMemory,
};

/// `buffer` holds the contents' reads; any length works with `stream`-
/// based reads.
pub fn init(gpa: Allocator, input: *Io.Reader, buffer: []u8, options: Options) Stream {
    return .{
        .gpa = gpa,
        .input = input,
        .options = options,
        .contents_ = .{ .interface = .{ .vtable = &Contents.vtable, .buffer = buffer, .seek = 0, .end = 0 } },
    };
}

pub fn deinit(s: *Stream) void {
    if (s.open) s.contents_.decoder.deinit();
    s.header.deinit(s.gpa);
    s.* = undefined;
}

/// The next entry, or null at the central directory. Its slices borrow
/// from the reader until the next call.
pub fn next(s: *Stream) NextError!?Record {
    if (s.done) return null;
    try s.skipRest();
    var sig_bytes: [4]u8 = undefined;
    const n = s.input.readSliceShort(&sig_bytes) catch return error.ReadFailed;
    if (n == 0) return s.fail(.truncated, error.Truncated);
    if (n < 4) return s.fail(.truncated, error.Truncated);
    const sig = std.mem.readInt(u32, &sig_bytes, .little);
    switch (sig) {
        format.local_sig => {},
        format.central_sig, format.end_sig, format.end64_sig => {
            s.done = true;
            return null;
        },
        else => return s.fail(.signature, error.Invalid),
    }
    if (Limits.full(s.options.limits.entries, s.entries)) return s.fail(.entries_limit, error.LimitExceeded);
    var fixed: [format.local_len]u8 = undefined;
    @memcpy(fixed[0..4], &sig_bytes);
    s.input.readSliceAll(fixed[4..]) catch |e| return switch (e) {
        error.EndOfStream => s.fail(.truncated, error.Truncated),
        error.ReadFailed => error.ReadFailed,
    };
    const local = format.Local.parse(&fixed);
    const var_len = @as(usize, local.name_len) + local.extra_len;
    if (Limits.over(s.options.limits.header, var_len)) return s.fail(.header_limit, error.LimitExceeded);
    s.header.clearRetainingCapacity();
    try s.header.resize(s.gpa, var_len);
    s.input.readSliceAll(s.header.items) catch |e| return switch (e) {
        error.EndOfStream => s.fail(.truncated, error.Truncated),
        error.ReadFailed => error.ReadFailed,
    };
    const name = s.header.items[0..local.name_len];
    const extra = s.header.items[local.name_len..];
    // The first ZIP64 field, found in the one pass that checks every field.
    var zip64_data: ?[]const u8 = null;
    var it: format.ExtraIterator = .{ .bytes = extra };
    while (it.next() catch return s.fail(.extra_field, error.Invalid)) |field| {
        if (field.id == format.Extra.zip64 and zip64_data == null) zip64_data = field.data;
    }
    var z: format.Zip64 = .{};
    if (zip64_data) |data| {
        z = format.Zip64.parse(data, local.size == 0xffffffff, local.compressed == 0xffffffff, false) catch return s.fail(.zip64, error.Invalid);
    }
    var r: Record = .{
        .entry = .{ .name = name, .size = z.size orelse local.size },
        .method = @fromBackingInt(@intCast(local.method)),
        .flags = local.flags,
        .crc = local.crc,
        .compressed = z.compressed orelse local.compressed,
        .offset = 0,
        .needed = local.needed,
        .dos_date = local.dos_date,
        .dos_time = local.dos_time,
        .raw_name = name,
        .extra = extra,
    };
    r.describe();
    if (r.encryption != .none) return s.fail(.unsupported_encryption, error.Unsupported);
    const descriptor = local.flags & format.Flags.descriptor != 0;
    if (descriptor and r.method == .stored) return s.fail(.unsupported_feature, error.Unsupported);
    try s.openContents(&r, descriptor, zip64_data != null);
    s.entries += 1;
    return r;
}

/// The current entry's contents: its CRC-32 and size checked at the end
/// against its header or its data descriptor.
pub fn contents(s: *Stream) *Io.Reader {
    return &s.contents_.interface;
}

pub const ContentsError = error{ SizeMismatch, CrcMismatch, Truncated, CorruptStream, InvalidDescriptor, LimitExceeded };

/// The error behind the contents' `error.ReadFailed`, when it was the
/// entry's and not the input's.
pub fn err(s: *const Stream) ?ContentsError {
    return s.contents_.failure;
}

fn fail(s: *Stream, reason: Diagnostic.Reason, e: anytype) @TypeOf(e) {
    Diagnostic.set(s.options.diagnostic, s.entries, 0, reason);
    return e;
}

fn openContents(s: *Stream, r: *const Record, descriptor: bool, zip64: bool) NextError!void {
    const c = &s.contents_;
    c.* = .{ .interface = c.interface, .owner = s, .descriptor = descriptor, .zip64 = zip64, .expected_crc = r.crc, .expected_size = r.entry.size };
    c.interface.seek = 0;
    c.interface.end = 0;
    var source: *Io.Reader = s.input;
    if (!descriptor) {
        c.bounded = .init(s.input, r.compressed, &c.bounded_buffer);
        source = &c.bounded.interface;
    }
    c.decoder.init(s.gpa, r.method, source, .{ .limits = s.options.limits, .self_terminated = descriptor }) catch |e| return switch (e) {
        error.UnsupportedMethod => blk: {
            if (s.options.diagnostic) |d| d.* = .{ .entry = s.entries, .reason = .unsupported_method, .method = @backingInt(r.method) };
            break :blk error.Unsupported;
        },
        error.LimitExceeded => s.fail(.window_limit, error.LimitExceeded),
        error.Invalid => s.fail(.codec, error.Invalid),
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
    s.open = true;
}

/// Reads what the caller left of the entry, through to its descriptor,
/// so the next header is next.
fn skipRest(s: *Stream) NextError!void {
    if (!s.open) return;
    const c = &s.contents_;
    c.interface.seek = 0;
    c.interface.end = 0;
    var scratch: [4096]u8 = undefined;
    while (true) {
        const n = c.interface.readSliceShort(&scratch) catch {
            const failure = c.failure;
            s.closeContents();
            return if (failure) |f| switch (f) {
                error.Truncated => error.Truncated,
                error.LimitExceeded => error.LimitExceeded,
                else => error.Invalid,
            } else error.ReadFailed;
        };
        if (n < scratch.len) break;
    }
    s.closeContents();
}

fn closeContents(s: *Stream) void {
    s.contents_.decoder.deinit();
    s.open = false;
}

const Contents = struct {
    interface: Io.Reader,
    owner: *Stream = undefined,
    bounded: Bounded = undefined,
    bounded_buffer: [16 * 1024]u8 = undefined,
    decoder: codec.Decoder = undefined,
    descriptor: bool = false,
    zip64: bool = false,
    expected_crc: u32 = 0,
    expected_size: u64 = 0,
    crc: warp.Crc32 = .init,
    size: u64 = 0,
    ended: bool = false,
    failure: ?ContentsError = null,

    const vtable: Io.Reader.VTable = .{ .stream = stream };

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const c: *Contents = @fieldParentPtr("interface", io_r);
        if (c.failure != null) return error.ReadFailed;
        if (c.ended) return error.EndOfStream;
        const room = if (c.descriptor) Limits.left(c.owner.options.limits.entry, c.size) else c.expected_size - c.size;
        const out = limit.min(.limited64(room +| 1)).slice(try w.writableSliceGreedy(1));
        const n = c.decoder.reader().readSliceShort(out) catch {
            if (c.bounded.failure != null and !c.descriptor) return c.fail(error.Truncated);
            if (c.decoder.failed()) return c.fail(error.CorruptStream);
            return error.ReadFailed;
        };
        if (n == 0) return c.finish();
        if (n > room) return c.fail(if (c.descriptor) error.LimitExceeded else error.SizeMismatch);
        c.crc.update(out[0..n]);
        c.size += n;
        w.advance(n);
        return n;
    }

    /// The decoder's end: the descriptor, when the entry has one, then
    /// the CRC-32 and size against what the archive declares.
    fn finish(c: *Contents) Io.Reader.StreamError {
        c.ended = true;
        if (c.descriptor) {
            const in = c.owner.input;
            var first: [4]u8 = undefined;
            readAll(in, &first) catch |e| return c.short(e);
            var crc = std.mem.readInt(u32, &first, .little);
            // The descriptor's signature is optional (APPNOTE 4.3.9.3).
            if (crc == format.descriptor_sig) {
                readAll(in, &first) catch |e| return c.short(e);
                crc = std.mem.readInt(u32, &first, .little);
            }
            var sizes: [16]u8 = undefined;
            const width: usize = if (c.zip64) 8 else 4;
            readAll(in, sizes[0 .. 2 * width]) catch |e| return c.short(e);
            const size = if (c.zip64) std.mem.readInt(u64, sizes[8..16], .little) else std.mem.readInt(u32, sizes[4..8], .little);
            c.expected_crc = crc;
            c.expected_size = size;
        }
        if (c.size != c.expected_size) return c.fail(error.SizeMismatch);
        if (c.crc.final() != c.expected_crc) return c.fail(error.CrcMismatch);
        return error.EndOfStream;
    }

    fn short(c: *Contents, e: error{ EndOfStream, ReadFailed }) Io.Reader.StreamError {
        return switch (e) {
            error.EndOfStream => c.fail(error.Truncated),
            error.ReadFailed => error.ReadFailed,
        };
    }

    fn fail(c: *Contents, e: ContentsError) error{ReadFailed} {
        c.failure = e;
        return error.ReadFailed;
    }
};

fn readAll(r: *Io.Reader, out: []u8) error{ EndOfStream, ReadFailed }!void {
    return r.readSliceAll(out);
}
