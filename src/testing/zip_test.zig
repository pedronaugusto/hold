const std = @import("std");
const hold = @import("../hold.zig");

fn readAll(gpa: std.mem.Allocator, archive: *hold.zip.Archive, record: hold.zip.Record) ![]u8 {
    var c: hold.zip.Archive.Contents = undefined;
    try archive.contents(&c, record, &.{}, .{});
    defer c.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = try c.reader().streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

test "a zip round-trips through every method warp has, streamed and in memory" {
    const gpa = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var zw: hold.zip.Writer = .init(gpa, &out.writer, .{});
    defer zw.deinit();
    const t: std.Io.Timestamp = hold.Entry.seconds(1_600_000_000);
    try zw.add(.{ .entry = .{ .name = "a.txt", .mtime = t } }, "hello hello hello hello");
    try zw.add(.{ .entry = .{ .name = "s.txt", .mtime = t }, .method = .stored }, "stored");
    try zw.add(.{ .entry = .{ .name = "z.txt", .mtime = t }, .method = .zstd }, "zstd zstd zstd zstd");
    try zw.add(.{ .entry = .{ .name = "dir/", .kind = .directory, .mtime = t } }, "");
    try zw.add(.{ .entry = .{ .name = "link", .kind = .symlink, .link = "a.txt", .mtime = t } }, "");
    const w = try zw.begin(.{ .entry = .{ .name = "streamed.bin", .mtime = t } });
    for (0..100) |i| try w.print("line {d}\n", .{i});
    try zw.end();
    const z = try zw.begin(.{ .entry = .{ .name = "streamed.zst", .mtime = t }, .method = .zstd, .zip64 = .always });
    try z.writeAll("zstd streamed");
    try zw.end();
    try zw.add(.{ .entry = .{ .name = "d\u{e9}.txt", .mtime = t } }, "unicode");
    try zw.finish("comment");

    var archive = try hold.zip.Archive.open(gpa, .{ .memory = out.written() }, .{});
    defer archive.deinit();
    try std.testing.expectEqual(@as(u64, 8), archive.len());
    try std.testing.expectEqualStrings("comment", archive.comment);
    const expect = [_]struct { name: []const u8, kind: hold.Entry.Kind, contents: []const u8 }{
        .{ .name = "a.txt", .kind = .file, .contents = "hello hello hello hello" },
        .{ .name = "s.txt", .kind = .file, .contents = "stored" },
        .{ .name = "z.txt", .kind = .file, .contents = "zstd zstd zstd zstd" },
        .{ .name = "dir/", .kind = .directory, .contents = "" },
        .{ .name = "link", .kind = .symlink, .contents = "a.txt" },
        .{ .name = "streamed.bin", .kind = .file, .contents = "" },
        .{ .name = "streamed.zst", .kind = .file, .contents = "zstd streamed" },
        .{ .name = "d\u{e9}.txt", .kind = .file, .contents = "unicode" },
    };
    var it = archive.iterate();
    var i: usize = 0;
    while (it.next()) |r| : (i += 1) {
        try std.testing.expectEqualStrings(expect[i].name, r.entry.name);
        try std.testing.expectEqual(expect[i].kind, r.entry.kind);
        try std.testing.expectEqual(t.nanoseconds, r.entry.mtime.?.nanoseconds);
        const got = try readAll(gpa, &archive, r);
        defer gpa.free(got);
        if (i == 5) {
            try std.testing.expect(std.mem.startsWith(u8, got, "line 0\nline 1\n"));
        } else try std.testing.expectEqualStrings(expect[i].contents, got);
    }
    try std.testing.expectEqual(hold.Entry.Encoding.utf8, archive.find("d\u{e9}.txt").?.entry.encoding);

    // The same archive read forward.
    var in: std.Io.Reader = .fixed(out.written());
    var st: hold.zip.Stream = .init(gpa, &in, &.{}, .{});
    defer st.deinit();
    var n: usize = 0;
    while (try st.next()) |r| : (n += 1) {
        var sink_buffer: [256]u8 = undefined;
        var sink: std.Io.Writer.Discarding = .init(&sink_buffer);
        _ = st.contents().streamRemaining(&sink.writer) catch |e| {
            std.debug.print("{s}: {any}\n", .{ r.entry.name, st.err() });
            return e;
        };
    }
    try std.testing.expectEqual(@as(usize, 8), n);
}

test "overlapping entries are refused when the archive is opened" {
    const gpa = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var zw: hold.zip.Writer = .init(gpa, &out.writer, .{});
    defer zw.deinit();
    try zw.add(.{ .entry = .{ .name = "a" }, .method = .stored }, "aaaa");
    try zw.add(.{ .entry = .{ .name = "b" }, .method = .stored }, "bbbb");
    try zw.finish("");
    // Point the second central record at the first local header: both
    // entries now share the same data, as Fifield's bomb shares it.
    const bytes = out.written();
    const dir = std.mem.findLast(u8, bytes, "PK\x01\x02").?;
    std.mem.writeInt(u32, bytes[dir + 42 ..][0..4], 0, .little);
    var diag: hold.Diagnostic = .{};
    try std.testing.expectError(error.Overlap, hold.zip.Archive.open(gpa, .{ .memory = bytes }, .{ .diagnostic = &diag }));
    try std.testing.expectEqual(hold.Diagnostic.Reason.overlap, diag.reason);
}
