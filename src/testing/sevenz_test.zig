//! 7z read: entries out of order, damage refused, the header's bounds.
const std = @import("std");
const hold = @import("../hold.zig");
const testdata = @import("testdata");

fn case(name: []const u8) []const u8 {
    for (testdata.sevenz) |c| if (std.mem.eql(u8, c.name, name)) return c.archive;
    unreachable; // unreachable: the tests name cases the index has
}

fn readAll(archive: *hold.sevenz.Archive, item: hold.sevenz.Item, out: []u8) ![]u8 {
    const r = try archive.contents(item, &.{});
    var w: std.Io.Writer = .fixed(out);
    _ = r.streamRemaining(&w) catch return archive.err() orelse error.ReadFailed;
    return w.buffered();
}

test "7z: a solid folder's entries read in any order" {
    const gpa = std.testing.allocator;
    var archive = try hold.sevenz.Archive.open(gpa, .{ .memory = case("sevenz/7zz-deflate.7z") }, .{});
    defer archive.deinit();
    const items = archive.entries();
    var buf: [64 * 1024]u8 = undefined;
    var first: [64 * 1024]u8 = undefined;
    // Last to first: each entry decodes its folder again up to it.
    var i = items.len;
    while (i > 0) {
        i -= 1;
        const it = items[i];
        if (it.entry.kind != .file) continue;
        const got = try readAll(&archive, it, &buf);
        try std.testing.expectEqual(it.entry.size, got.len);
    }
    // In order, and one entry left half read before the next.
    for (items) |it| {
        if (it.entry.kind != .file or it.entry.size < 10) continue;
        const r = try archive.contents(it, &.{});
        _ = try r.readSliceShort(first[0..5]);
    }
    for (items) |it| {
        if (it.entry.kind != .file) continue;
        _ = try readAll(&archive, it, &buf);
    }
}

test "7z: a changed byte fails its entry's CRC" {
    const gpa = std.testing.allocator;
    const original = case("sevenz/7zz-copy.7z");
    const bytes = try gpa.dupe(u8, original);
    defer gpa.free(bytes);
    // Copy stores the contents as they are: the first packed bytes are
    // the first file's.
    bytes[32] ^= 1;
    var archive = try hold.sevenz.Archive.open(gpa, .{ .memory = bytes }, .{});
    defer archive.deinit();
    var buf: [64 * 1024]u8 = undefined;
    var failed = false;
    for (archive.entries()) |it| {
        if (it.folder == null) continue;
        _ = readAll(&archive, it, &buf) catch |e| {
            try std.testing.expectEqual(error.CrcMismatch, e);
            failed = true;
            break;
        };
    }
    try std.testing.expect(failed);
}

test "7z: a changed header fails its CRC, a cut archive is truncated" {
    const gpa = std.testing.allocator;
    const original = case("sevenz/7zz-deflate.7z");
    const bytes = try gpa.dupe(u8, original);
    defer gpa.free(bytes);
    bytes[bytes.len - 3] ^= 1;
    try std.testing.expectError(error.Corrupt, hold.sevenz.Archive.open(gpa, .{ .memory = bytes }, .{}));
    try std.testing.expectError(error.Truncated, hold.sevenz.Archive.open(gpa, .{ .memory = original[0 .. original.len - 1] }, .{}));
    try std.testing.expectError(error.Invalid, hold.sevenz.Archive.open(gpa, .{ .memory = "7z" }, .{}));
}

test "7z: the header's bounds hold" {
    const gpa = std.testing.allocator;
    const bytes = case("sevenz/7zz-deflate.7z");
    try std.testing.expectError(error.LimitExceeded, hold.sevenz.Archive.open(gpa, .{ .memory = bytes }, .{ .limits = .{ .directory = .fromRaw(16) } }));
    try std.testing.expectError(error.LimitExceeded, hold.sevenz.Archive.open(gpa, .{ .memory = bytes }, .{ .limits = .{ .entries = .fromRaw(2) } }));
}

test "7z: an encrypted folder wants the password" {
    const gpa = std.testing.allocator;
    var archive = try hold.sevenz.Archive.open(gpa, .{ .memory = case("sevenz/7zz-aes-deflate.7z") }, .{});
    defer archive.deinit();
    for (archive.entries()) |it| {
        if (it.folder == null) continue;
        try std.testing.expect(it.encrypted);
        try std.testing.expectError(error.PasswordRequired, archive.contents(it, &.{}));
    }
}

/// One copied file "a" holding "abc", its header written by hand: the
/// fuzz target's seed.
const hand_header = "\x01\x04\x06\x00\x01\x09\x03\x00\x07\x0b\x01\x00\x01\x01\x00\x0c\x03\x00\x08\x0a\x01\xc2\x41\x24\x35\x00\x00\x05\x01\x11\x05\x00\x61\x00\x00\x00\x00\x00";

test "7z: a header written by hand reads" {
    const gpa = std.testing.allocator;
    const crc32 = @import("warp").crc32;
    var bytes: [32 + 3 + hand_header.len]u8 = undefined;
    @memcpy(bytes[0..6], "7z\xbc\xaf\x27\x1c");
    bytes[6] = 0;
    bytes[7] = 4;
    std.mem.writeInt(u64, bytes[12..20], 3, .little);
    std.mem.writeInt(u64, bytes[20..28], hand_header.len, .little);
    std.mem.writeInt(u32, bytes[28..32], crc32(0, hand_header), .little);
    std.mem.writeInt(u32, bytes[8..12], crc32(0, bytes[12..32]), .little);
    @memcpy(bytes[32..35], "abc");
    @memcpy(bytes[35..], hand_header);
    var archive = try hold.sevenz.Archive.open(gpa, .{ .memory = &bytes }, .{});
    defer archive.deinit();
    try std.testing.expectEqual(@as(usize, 1), archive.entries().len);
    const item = archive.entries()[0];
    try std.testing.expectEqualStrings("a", item.entry.name);
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings("abc", try readAll(&archive, item, &buf));
}
