const std = @import("std");
const hold = @import("../hold.zig");

test "a pax archive round-trips" {
    const gpa = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var tw: hold.tar.Writer = .init(&out.writer, &.{}, .{});
    try tw.add(.{ .entry = .{ .name = "a.txt", .size = 5, .mode = 0o644 } }, "hello");
    try tw.add(.{ .entry = .{ .name = "dir/", .kind = .directory } }, "");
    const long = "d/" ++ rep('x', 200);
    try tw.add(.{ .entry = .{ .name = long, .mtime = .{ .nanoseconds = 1_500_000_000 } }, .exact_times = true }, "long");
    try tw.finish();
    try std.testing.expectEqual(@as(usize, 0), out.written().len % 10240);

    var in: std.Io.Reader = .fixed(out.written());
    var tr: hold.tar.Reader = .init(gpa, &in, &.{}, .{});
    defer tr.deinit();
    const a = (try tr.next()).?;
    try std.testing.expectEqualStrings("a.txt", a.name);
    try std.testing.expectEqual(@as(u64, 5), a.size);
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    _ = try tr.contents().streamRemaining(&w);
    try std.testing.expectEqualStrings("hello", w.buffered());
    const d = (try tr.next()).?;
    try std.testing.expectEqual(hold.Entry.Kind.directory, d.kind);
    const l = (try tr.next()).?;
    try std.testing.expectEqualStrings(long, l.name);
    try std.testing.expectEqual(@as(i96, 1_500_000_000), l.mtime.?.nanoseconds);
    try std.testing.expectEqual(@as(?hold.Entry, null), try tr.next());
}

fn rep(comptime c: u8, comptime n: usize) [n]u8 {
    return @splat(c);
}
