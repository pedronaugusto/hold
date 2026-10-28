//! pax extended header records (POSIX.1-2001): "<length> <key>=<value>\n",
//! the length counting the whole record, its own digits included.
const std = @import("std");
const Io = std.Io;
const time = @import("../time.zig");

pub const Record = struct { key: []const u8, value: []const u8 };

pub const ParseError = error{InvalidRecord};

/// The records of an extended header's data, in order.
pub const Iterator = struct {
    data: []const u8,
    at: usize = 0,

    pub fn next(it: *Iterator) ParseError!?Record {
        // A header's data is padded with NULs by some writers.
        if (it.at == it.data.len or it.data[it.at] == 0) return null;
        const rest = it.data[it.at..];
        const space = std.mem.findScalar(u8, rest[0..@min(rest.len, 21)], ' ') orelse return error.InvalidRecord;
        if (space == 0) return error.InvalidRecord;
        const len = std.fmt.parseUnsigned(usize, rest[0..space], 10) catch return error.InvalidRecord;
        if (len <= space + 1 or len > rest.len or rest[len - 1] != '\n') return error.InvalidRecord;
        const body = rest[space + 1 .. len - 1];
        const eq = std.mem.findScalar(u8, body, '=') orelse return error.InvalidRecord;
        if (eq == 0) return error.InvalidRecord;
        it.at += len;
        return .{ .key = body[0..eq], .value = body[eq + 1 ..] };
    }
};

/// The record's length: the digits of the length count themselves.
pub fn recordLen(key: []const u8, value: []const u8) usize {
    const body = key.len + value.len + 3; // ' ', '=', '\n'
    var digits: usize = 1;
    while (true) {
        const len = body + digits;
        const need = std.math.log10_int(len) + 1;
        if (need == digits) return len;
        digits = need;
    }
}

pub fn write(w: *Io.Writer, key: []const u8, value: []const u8) Io.Writer.Error!void {
    try w.print("{d} {s}=", .{ recordLen(key, value), key });
    try w.writeAll(value);
    try w.writeByte('\n');
}

pub const TimeError = error{InvalidTime};

/// A pax time: decimal seconds since the epoch with an optional fraction,
/// possibly negative ("-1.25" is a quarter past a second before 1970).
pub fn parseTime(text: []const u8) TimeError!Io.Timestamp {
    var s = text;
    const negative = s.len != 0 and s[0] == '-';
    if (negative) s = s[1..];
    const dot = std.mem.findScalar(u8, s, '.') orelse s.len;
    if (dot == 0) return error.InvalidTime;
    // Seconds past an i64's, some 292 billion years, are no time.
    const whole = std.fmt.parseUnsigned(u63, s[0..dot], 10) catch return error.InvalidTime;
    var nanos: u32 = 0;
    if (dot < s.len) {
        const frac = s[dot + 1 ..];
        if (frac.len == 0) return error.InvalidTime;
        var scale: u32 = 100_000_000;
        for (frac) |c| {
            if (c < '0' or c > '9') return error.InvalidTime;
            nanos += (c - '0') * scale;
            scale /= 10;
        }
    }
    return time.fromParts(negative, whole, nanos);
}

/// A time as `parseTime` reads it: whole seconds, and a fraction only when
/// there is one, its trailing zeros dropped.
pub fn formatTime(t: Io.Timestamp, buffer: *[40]u8) []const u8 {
    const p = time.parts(t);
    const sign = if (p.negative) "-" else "";
    const secs = p.whole;
    var frac = p.nanos;
    if (frac == 0) return std.mem.print(buffer, "{s}{d}", .{ sign, secs }) catch unreachable; // 40 bytes hold any i96 time: a sign, 20 digits of seconds and ten of the fraction
    var digits: usize = 9;
    while (frac % 10 == 0) {
        frac /= 10;
        digits -= 1;
    }
    return std.mem.print(buffer, "{s}{d}.{d:0>[3]}", .{ sign, secs, frac, digits }) catch unreachable; // 40 bytes hold any i96 time: a sign, 20 digits of seconds and ten of the fraction
}

test Iterator {
    var it: Iterator = .{ .data = "30 mtime=1350244992.023960108\n6 a=b\n\x00\x00" };
    const r = (try it.next()).?;
    try std.testing.expectEqualStrings("mtime", r.key);
    try std.testing.expectEqualStrings("1350244992.023960108", r.value);
    try std.testing.expectEqualStrings("b", (try it.next()).?.value);
    try std.testing.expectEqual(@as(?Record, null), try it.next());
    var bad: Iterator = .{ .data = "7 a=b\n" };
    try std.testing.expectError(error.InvalidRecord, bad.next());
    var empty_value: Iterator = .{ .data = "8 path=\n" };
    try std.testing.expectEqualStrings("", (try empty_value.next()).?.value);
}

test recordLen {
    try std.testing.expectEqual(@as(usize, 30), recordLen("mtime", "1350244992.023960108"));
    // 9 bytes of body and one digit make 10, which needs two.
    try std.testing.expectEqual(@as(usize, 11), recordLen("path", "ab"));
}

test parseTime {
    try std.testing.expectEqual(@as(i96, 1_350_244_992_023_960_108), (try parseTime("1350244992.023960108")).nanoseconds);
    try std.testing.expectEqual(@as(i96, -1_250_000_000), (try parseTime("-1.25")).nanoseconds);
    try std.testing.expectError(error.InvalidTime, parseTime("1.x"));
    var buf: [40]u8 = undefined;
    try std.testing.expectEqualStrings("-1.25", formatTime(.{ .nanoseconds = -1_250_000_000 }, &buf));
    try std.testing.expectEqualStrings("7", formatTime(.{ .nanoseconds = 7_000_000_000 }, &buf));
}
