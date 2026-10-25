//! A fuzz target for every parser of untrusted input: each takes the bytes
//! the fuzzer makes as an archive, or a field, and must refuse them by a
//! named error or read them, never crash or loop.
const std = @import("std");
const hold = @import("../hold.zig");
const pax = @import("../tar/pax.zig");
const header = @import("../tar/header.zig");

fn tarArchive(_: void, smith: *std.testing.Smith) !void {
    var bytes: [4096]u8 = undefined;
    const n = smith.slice(&bytes);
    var in: std.Io.Reader = .fixed(bytes[0..n]);
    var tr: hold.tar.Reader = .init(std.testing.allocator, &in, &.{}, .{ .limits = .{ .header = .fromRaw(2048) } });
    defer tr.deinit();
    var count: usize = 0;
    while (count < 64) : (count += 1) {
        const entry = tr.next() catch |e| switch (e) {
            error.Invalid, error.Truncated, error.LimitExceeded => return,
            else => return e,
        } orelse return;
        var sink: std.Io.Writer.Discarding = .init(&.{});
        const got = tr.contents().streamRemaining(&sink.writer) catch |e| switch (e) {
            error.ReadFailed => {
                try std.testing.expect(tr.err() != null);
                return;
            },
            else => return e,
        };
        try std.testing.expectEqual(entry.size, got);
    }
}

test "fuzz_test: tar archives" {
    try std.testing.fuzz({}, tarArchive, .{ .corpus = &.{
        "",
        "ustar\x0000",
    } });
}

fn paxRecords(_: void, smith: *std.testing.Smith) !void {
    var bytes: [512]u8 = undefined;
    const n = smith.slice(&bytes);
    var it: pax.Iterator = .{ .data = bytes[0..n] };
    while (it.next() catch return) |rec| {
        if (pax.parseTime(rec.value)) |_| {} else |e| try std.testing.expectEqual(error.InvalidTime, e);
    }
}

test "fuzz_test: pax records and times" {
    try std.testing.fuzz({}, paxRecords, .{ .corpus = &.{ "30 mtime=1350244992.023960108\n", "6 a=b\n" } });
}

fn numbers(_: void, smith: *std.testing.Smith) !void {
    var bytes: [12]u8 = undefined;
    const n = smith.slice(&bytes);
    if (header.signed(bytes[0..n])) |v| {
        _ = v;
    } else |e| try std.testing.expectEqual(error.InvalidNumber, e);
}

test "fuzz_test: header numbers" {
    try std.testing.fuzz({}, numbers, .{ .corpus = &.{ "0000644\x00", "\x80\x00\x00\x01" } });
}
