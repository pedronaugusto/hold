//! Exactly `n` bytes of an archive's stream: an entry's stored bytes. An
//! archive that ends before them is `Truncated`, never a short entry.
const Bounded = @This();

const std = @import("std");
const Io = std.Io;

interface: Io.Reader,
/// Private: the archive.
inner: *Io.Reader,
/// Private: bytes still to give.
left: u64,
failure: ?Error = null,

pub const Error = error{
    /// The archive ended inside the entry.
    Truncated,
};

/// `buffer` stages the bytes for a reader above that reads them in place
/// (warp's decoders peek at their input); any length otherwise.
pub fn init(inner: *Io.Reader, n: u64, buffer: []u8) Bounded {
    return .{ .interface = .{ .vtable = &vtable, .buffer = buffer, .seek = 0, .end = 0 }, .inner = inner, .left = n };
}

const vtable: Io.Reader.VTable = .{ .stream = stream, .discard = discard };

fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const b: *Bounded = @fieldParentPtr("interface", io_r);
    if (b.left == 0) return error.EndOfStream;
    const n = b.inner.stream(w, limit.min(.limited64(b.left))) catch |e| switch (e) {
        error.EndOfStream => return b.truncated(),
        else => |other| return other,
    };
    b.left -= n;
    return n;
}

fn discard(io_r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
    const b: *Bounded = @fieldParentPtr("interface", io_r);
    if (b.left == 0) return error.EndOfStream;
    const n = b.inner.discard(limit.min(.limited64(b.left))) catch |e| switch (e) {
        error.EndOfStream => return b.truncated(),
        else => |other| return other,
    };
    b.left -= n;
    return n;
}

fn truncated(b: *Bounded) error{ReadFailed} {
    b.failure = error.Truncated;
    return error.ReadFailed;
}

test "an archive ending early is truncated, not short" {
    var in: Io.Reader = .fixed("abc");
    var b: Bounded = .init(&in, 5, &.{});
    var buf: [8]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try std.testing.expectError(error.ReadFailed, b.interface.streamRemaining(&w));
    try std.testing.expectEqual(@as(?Error, error.Truncated), b.failure);
}
