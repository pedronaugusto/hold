//! A consumer imports the one module and reaches every part with only its
//! runtime dependencies.
const std = @import("std");
const hold = @import("hold");

pub fn main() !void {
    var buffer: [10240]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var tw: hold.tar.Writer = .init(&out, &.{}, .{});
    try tw.add(.{ .entry = .{ .name = "a" } }, "a");
    try tw.finish();
}
