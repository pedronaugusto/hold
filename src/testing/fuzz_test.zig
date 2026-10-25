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

fn zipArchive(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var bytes: [4096]u8 = undefined;
    const n = smith.slice(&bytes);
    var archive = hold.zip.Archive.open(gpa, .{ .memory = bytes[0..n] }, .{ .limits = .{ .window = .fromRaw(1 << 20) } }) catch |e| switch (e) {
        error.Invalid, error.Unsupported, error.Overlap, error.LimitExceeded, error.Truncated => return,
        else => return e,
    };
    defer archive.deinit();
    var it = archive.iterate();
    var count: usize = 0;
    while (it.next()) |record| : (count += 1) {
        if (count == 32) break;
        var c: hold.zip.Archive.Contents = undefined;
        archive.contents(&c, record, &.{}, .{}) catch continue; // a refused entry is named by its error; the next is read
        defer c.deinit();
        var sink_buffer: [256]u8 = undefined;
        var sink: std.Io.Writer.Discarding = .init(&sink_buffer);
        const got = c.reader().streamRemaining(&sink.writer) catch {
            try std.testing.expect(c.err() != null);
            continue;
        };
        try std.testing.expectEqual(record.entry.size, got);
    }
}

test "fuzz_test: zip archives through the central directory" {
    try std.testing.fuzz({}, zipArchive, .{ .corpus = &.{
        "PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    } });
}

fn zipStream(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var bytes: [4096]u8 = undefined;
    const n = smith.slice(&bytes);
    var in: std.Io.Reader = .fixed(bytes[0..n]);
    var st: hold.zip.Stream = .init(gpa, &in, &.{}, .{ .limits = .{ .window = .fromRaw(1 << 20), .entry = .fromRaw(1 << 20) } });
    defer st.deinit();
    var count: usize = 0;
    while (count < 32) : (count += 1) {
        const record = st.next() catch |e| switch (e) {
            error.Invalid, error.Unsupported, error.LimitExceeded, error.Truncated => return,
            else => return e,
        } orelse return;
        _ = record;
        var sink_buffer: [256]u8 = undefined;
        var sink: std.Io.Writer.Discarding = .init(&sink_buffer);
        _ = st.contents().streamRemaining(&sink.writer) catch {
            try std.testing.expect(st.err() != null);
            return;
        };
    }
}

test "fuzz_test: zip archives read forward" {
    try std.testing.fuzz({}, zipStream, .{ .corpus = &.{"PK\x03\x04"} });
}

/// A 7z archive around the fuzzer's bytes: the first two give the
/// header's length, the rest are packed streams then the header, and the
/// start header's CRCs are made right, so the header parser and the
/// folders' decoders see the bytes and not a checksum refusal.
fn sevenzArchive(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var bytes: [4096]u8 = undefined;
    const n = smith.slice(&bytes);
    if (n < 2) return;
    const rest = bytes[2..n];
    const header_len = std.mem.readInt(u16, bytes[0..2], .little) % (rest.len + 1);
    var archive_bytes: [32 + 4096]u8 = undefined;
    const start = archive_bytes[0..32];
    @memcpy(start[0..6], "7z\xbc\xaf\x27\x1c");
    start[6] = 0;
    start[7] = 4;
    std.mem.writeInt(u64, start[12..20], rest.len - header_len, .little);
    std.mem.writeInt(u64, start[20..28], header_len, .little);
    std.mem.writeInt(u32, start[28..32], @import("warp").crc32(0, rest[rest.len - header_len ..]), .little);
    std.mem.writeInt(u32, start[8..12], @import("warp").crc32(0, start[12..32]), .little);
    @memcpy(archive_bytes[32..][0..rest.len], rest);
    var archive = hold.sevenz.Archive.open(gpa, .{ .memory = archive_bytes[0 .. 32 + rest.len] }, .{ .limits = .{ .window = .fromRaw(1 << 20) } }) catch |e| switch (e) {
        error.Invalid, error.Corrupt, error.Unsupported, error.UnsupportedMethod, error.UnsupportedEncryption, error.PasswordRequired, error.LimitExceeded, error.Truncated => return,
        else => return e,
    };
    defer archive.deinit();
    for (archive.entries(), 0..) |item, count| {
        if (count == 32) break;
        const r = archive.contents(item, &.{}) catch continue; // a refused entry is named by its error; the next is read
        var sink_buffer: [256]u8 = undefined;
        var sink: std.Io.Writer.Discarding = .init(&sink_buffer);
        const got = r.streamRemaining(&sink.writer) catch {
            try std.testing.expect(archive.err() != null);
            continue;
        };
        try std.testing.expectEqual(item.entry.size, got);
    }
}

test "fuzz_test: 7z archives" {
    try std.testing.fuzz({}, sevenzArchive, .{
        .corpus = &.{
            // One copied file "a" of three bytes, "abc" (sevenz_test.zig).
            "\x26\x00abc\x01\x04\x06\x00\x01\x09\x03\x00\x07\x0b\x01\x00\x01\x01\x00\x0c\x03\x00\x08\x0a\x01\xc2\x41\x24\x35\x00\x00\x05\x01\x11\x05\x00\x61\x00\x00\x00\x00\x00",
        },
    });
}
