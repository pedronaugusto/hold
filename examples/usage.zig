//! README.md's Usage, built and run by the tests.
const std = @import("std");
const hold = @import("hold");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    // --- README:usage ---
    // Write a tar archive: pax where a name or number needs it.
    var archive: std.Io.Writer.Allocating = .init(gpa);
    defer archive.deinit();
    var tw: hold.tar.Writer = .init(&archive.writer, &.{}, .{});
    try tw.add(.{ .entry = .{ .name = "hello.txt", .mode = 0o644 } }, "hello, world\n");
    try tw.finish();

    // Read it back, an entry at a time.
    var input: std.Io.Reader = .fixed(archive.written());
    var tr: hold.tar.Reader = .init(gpa, &input, &.{}, .{});
    defer tr.deinit();
    while (try tr.next()) |entry| {
        var buffer: [64]u8 = undefined;
        var contents: std.Io.Writer = .fixed(&buffer);
        _ = try tr.contents().streamRemaining(&contents);
        std.debug.assert(std.mem.eql(u8, entry.name, "hello.txt"));
        std.debug.assert(std.mem.eql(u8, contents.buffered(), "hello, world\n"));
    }
    // --- README:usage ---
}
