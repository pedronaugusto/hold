//! An entry's decoded contents, held to what the archive declared: exactly
//! `size` bytes, then the decoder's own end, and the CRC-32 the archive
//! gives. A decoder that would give more is cut at the declared size and
//! refused (design §3: every byte written was declared first).
const Checked = @This();

const std = @import("std");
const Io = std.Io;
const warp = @import("warp");

interface: Io.Reader,
/// Private: the decoded bytes.
inner: *Io.Reader,
/// Private: bytes still owed.
left: u64,
crc: warp.Crc32 = .init,
/// Private: the CRC-32 the archive declares, or null where it gives none
/// (an AE-2 encrypted entry, authenticated instead).
expected: ?u32,
/// Private: whether the decoder must end with these bytes. A 7z entry
/// that is one of several in a folder's stream is followed by the next.
ends: bool = true,
failure: ?Error = null,

pub const Error = error{
    /// The decoder gave fewer or more bytes than the archive declares.
    SizeMismatch,
    /// The contents' CRC-32 is not the archive's.
    CrcMismatch,
};

/// `buffer` holds the contents' reads; any length, zero included, works
/// with `stream`-based reads.
pub fn init(inner: *Io.Reader, size: u64, expected: ?u32, buffer: []u8) Checked {
    return .{
        .interface = .{ .vtable = &vtable, .buffer = buffer, .seek = 0, .end = 0 },
        .inner = inner,
        .left = size,
        .expected = expected,
    };
}

const vtable: Io.Reader.VTable = .{ .stream = stream, .discard = discard };

fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const c: *Checked = @fieldParentPtr("interface", io_r);
    if (c.left == 0) return c.end();
    const out = limit.min(.limited64(c.left)).slice(try w.writableSliceGreedy(1));
    const n = try c.take(out);
    w.advance(n);
    return n;
}

fn discard(io_r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
    const c: *Checked = @fieldParentPtr("interface", io_r);
    if (c.left == 0) return c.end();
    var scratch: [4096]u8 = undefined;
    return c.take(limit.min(.limited64(c.left)).slice(&scratch));
}

/// Reads what the decoder gives into `out`, at least a byte.
fn take(c: *Checked, out: []u8) Io.Reader.Error!usize {
    const n = try c.inner.readSliceShort(out);
    if (n == 0) return c.fail(error.SizeMismatch);
    c.crc.update(out[0..n]);
    c.left -= n;
    return n;
}

/// The first `size` bytes of `inner`, which go on past them: a part of a
/// stream another reader continues.
pub fn initPart(inner: *Io.Reader, size: u64, expected: ?u32, buffer: []u8) Checked {
    var c: Checked = .init(inner, size, expected, buffer);
    c.ends = false;
    return c;
}

/// After the declared bytes: the decoder must end there, and the CRC
/// must match.
fn end(c: *Checked) Io.Reader.Error {
    if (c.failure != null) return error.ReadFailed;
    if (!c.ends) {
        if (c.expected) |want| if (c.crc.final() != want) return c.fail(error.CrcMismatch);
        return error.EndOfStream;
    }
    _ = c.inner.peekByte() catch |e| switch (e) {
        error.EndOfStream => {
            if (c.expected) |want| if (c.crc.final() != want) return c.fail(error.CrcMismatch);
            return error.EndOfStream;
        },
        error.ReadFailed => return error.ReadFailed,
    };
    return c.fail(error.SizeMismatch);
}

fn fail(c: *Checked, e: Error) error{ReadFailed} {
    c.failure = e;
    return error.ReadFailed;
}

test "more bytes than declared are refused at the declared size" {
    var in: Io.Reader = .fixed("hello, world");
    var c: Checked = .init(&in, 5, null, &.{});
    var buf: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try std.testing.expectError(error.ReadFailed, c.interface.streamRemaining(&w));
    try std.testing.expectEqualStrings("hello", w.buffered());
    try std.testing.expectEqual(@as(?Error, error.SizeMismatch), c.failure);
}

test "the CRC is checked at the end" {
    var in: Io.Reader = .fixed("hello");
    var c: Checked = .init(&in, 5, warp.crc32(0, "hello"), &.{});
    var sink_buffer: [64]u8 = undefined;
    var sink: Io.Writer.Discarding = .init(&sink_buffer);
    try std.testing.expectEqual(@as(usize, 5), try c.interface.streamRemaining(&sink.writer));
    var bad_in: Io.Reader = .fixed("hellp");
    var bad: Checked = .init(&bad_in, 5, warp.crc32(0, "hello"), &.{});
    try std.testing.expectError(error.ReadFailed, bad.interface.streamRemaining(&sink.writer));
    try std.testing.expectEqual(@as(?Error, error.CrcMismatch), bad.failure);
}
