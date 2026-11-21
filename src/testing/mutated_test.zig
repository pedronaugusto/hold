//! Crafted input, as properties: bytes made from archives hold wrote,
//! changed where their lengths and offsets lie, then read as a consumer
//! reads them. Every read either succeeds within its limits or is refused
//! with an error; nothing panics, nothing is read outside the input, and an
//! entry's contents never run past the size the archive declared, and no
//! allocation passes what the limits allow.
const std = @import("std");
const shakedown = @import("shakedown");
const hold = @import("../hold.zig");

const testing = std.testing;
const gen = shakedown.gen;

/// The limits the properties read under: small, so that a declared length
/// meets them.
const limits: hold.Limits = .{
    .header = .fromRaw(4096),
    .directory = .fromRaw(64 * 1024),
    .entries = .fromRaw(64),
    .window = .fromRaw(1 << 20),
};

/// The most of one entry's contents a case reads: a bomb's declared size
/// is checked by what it gives up to here.
const most_read = 1 << 20;

/// `out` made from one of `examples`, mutated: shakedown's edits, then,
/// half the time, a 16- or 32-bit field in the last 128 bytes set to a
/// drawn value (a zip's directory and end record lie there; a tar's last
/// header and its padding).
fn draw(s: *shakedown.Source, out: []u8, examples: []const []const u8) []u8 {
    const bytes = gen.mutated(s, out, examples);
    if (bytes.len < 4 or !gen.boolean(s)) return bytes;
    const from = bytes.len -| 128;
    const at = gen.intRange(s, usize, from, bytes.len - 2);
    const values = [_]u32{ 0, 1, 0xffff, 0xffffffff, 0x8000, 46, 30 };
    const v = if (gen.boolean(s)) gen.oneOf(s, u32, &values) else gen.int(s, u32);
    if (at + 4 <= bytes.len and gen.boolean(s)) {
        std.mem.writeInt(u32, bytes[at..][0..4], v, .little);
    } else std.mem.writeInt(u16, bytes[at..][0..2], @truncate(v), .little);
    return bytes;
}

/// Reads at most `most_read` bytes of `r` and returns how many it gave,
/// or the read's failure.
fn drain(r: *std.Io.Reader) error{ ReadFailed, WriteFailed }!u64 {
    var space: [512]u8 = undefined;
    var sink: std.Io.Writer.Discarding = .init(&space);
    var total: u64 = 0;
    while (total < most_read) {
        total += r.stream(&sink.writer, .limited(most_read - total)) catch |e| switch (e) {
            error.EndOfStream => return total,
            error.ReadFailed, error.WriteFailed => |f| return f,
        };
    }
    return total;
}

/// A local header, a central directory record whose name, extra and
/// comment lengths pass 64 KiB together (0xffff each, against a 46-byte
/// directory), and an end record of one entry, the directory 46 bytes at
/// 30: 98 bytes. The shape whose u16 sum overflowed std's zip reader.
const wide_lengths: [98]u8 = blk: {
    var b: [98]u8 = @splat(0);
    b[0..4].* = .{ 'P', 'K', 3, 4 };
    b[30..34].* = .{ 'P', 'K', 1, 2 };
    // name, extra and comment lengths, at 28, 30 and 32 in the record.
    for ([_]usize{ 30 + 28, 30 + 30, 30 + 32 }) |at| b[at..][0..2].* = .{ 0xff, 0xff };
    b[76..80].* = .{ 'P', 'K', 5, 6 };
    // entries on this disk and in all, at 8 and 10; size at 12; offset at 16.
    b[76 + 8] = 1;
    b[76 + 10] = 1;
    b[76 + 12] = 46;
    b[76 + 16] = 30;
    break :blk b;
};

fn writeZips(gpa: std.mem.Allocator, out: *[4][]u8) !void {
    const t = hold.Entry.seconds(1_600_000_000);
    const body = "the contents, the contents, the contents of an entry\n";
    const bodies = body ++ body ++ body ++ body;
    for (out, 0..) |*o, i| {
        var w: std.Io.Writer.Allocating = .init(gpa);
        errdefer w.deinit();
        var zw: hold.zip.Writer = .init(gpa, &w.writer, .{});
        defer zw.deinit();
        switch (i) {
            0 => {
                try zw.add(.{ .entry = .{ .name = "a", .mtime = t }, .method = .stored }, body);
                try zw.add(.{ .entry = .{ .name = "dir/", .kind = .directory, .mtime = t } }, "");
            },
            1 => try zw.add(.{ .entry = .{ .name = "deflated", .mtime = t }, .method = .deflate }, bodies),
            2 => try zw.add(.{ .entry = .{ .name = "z", .mtime = t }, .method = .zstd }, bodies),
            else => {
                // Streamed: sizes and CRC in a data descriptor after the data.
                const sw = try zw.begin(.{ .entry = .{ .name = "streamed", .mtime = t }, .method = .deflate });
                try sw.writeAll(body);
                try zw.end();
            },
        }
        try zw.finish(if (i == 0) "a comment" else "");
        o.* = try w.toOwnedSlice();
    }
}

/// One mutated zip, read through its central directory: opened, listed,
/// and each entry's contents read.
fn zipOne(examples: []const []const u8, case: *shakedown.Case) anyerror!void {
    var counting: shakedown.alloc.Counting = .init(testing.allocator);
    try zipRead(examples, case, counting.allocator());
    // Nothing is allocated past what the limits allow: the directory, a
    // codec's window, and the buffers around them.
    const allowed = try (try limits.directory.add(limits.window)).add(.literal("256KiB"));
    try testing.expect(allowed.compare(.fromRaw(counting.peak_bytes)) != .lt);
}

fn zipRead(examples: []const []const u8, case: *shakedown.Case, gpa: std.mem.Allocator) anyerror!void {
    var buffer: [2048]u8 = undefined;
    const bytes = draw(case.source, &buffer, examples);
    var archive = hold.zip.Archive.open(gpa, .{ .memory = bytes }, .{ .limits = limits }) catch |e| switch (e) {
        error.Invalid, error.Unsupported, error.Overlap, error.LimitExceeded, error.Truncated => return,
        else => return e,
    };
    defer archive.deinit();
    try testing.expect(limits.entries.compare(.fromRaw(archive.len())) != .lt);
    var listed: u64 = 0;
    var it = archive.iterate();
    while (it.next()) |r| {
        listed += 1;
        // An entry's stored bytes lie inside the input.
        try testing.expect(r.offset < bytes.len);
        try testing.expect(r.compressed <= bytes.len);
        var c: hold.zip.Archive.Contents = undefined;
        archive.contents(&c, r, &.{}, .{}) catch |e| switch (e) {
            error.Invalid, error.UnsupportedMethod, error.UnsupportedEncryption, error.PasswordRequired, error.LimitExceeded, error.Truncated => continue,
            else => return e,
        };
        defer c.deinit();
        const got = drain(c.reader()) catch |e| switch (e) {
            error.ReadFailed => {
                try testing.expect(c.err() != null);
                continue;
            },
            else => return e,
        };
        // Never past the declared size; all of it when it is read whole.
        try testing.expect(got <= r.entry.size);
        if (got < most_read) try testing.expectEqual(r.entry.size, got);
    }
    try testing.expectEqual(archive.len(), listed);
}

test "any bytes made from a zip open, list and read within their limits, or are refused" {
    const gpa = testing.allocator;
    var zips: [4][]u8 = undefined;
    try writeZips(gpa, &zips);
    defer for (zips) |z| gpa.free(z);
    const examples = [_][]const u8{ zips[0], zips[1], zips[2], zips[3], &wide_lengths };
    try shakedown.check(gpa, @as([]const []const u8, &examples), zipOne, .{ .cases = 3000 });
}

test "a directory record whose lengths pass 64 KiB together is refused" {
    try testing.expectError(error.Invalid, hold.zip.Archive.open(testing.allocator, .{ .memory = &wide_lengths }, .{}));
}

fn writeTars(gpa: std.mem.Allocator, out: *[3][]u8) !void {
    const long_name: [150]u8 = @splat('n');
    const long_link: [120]u8 = @splat('l');
    const t = hold.Entry.seconds(1_600_000_000);
    const formats = [_]hold.tar.Writer.Format{ .pax, .gnu, .ustar };
    for (out, formats) |*o, format| {
        var w: std.Io.Writer.Allocating = .init(gpa);
        errdefer w.deinit();
        var tw: hold.tar.Writer = .init(&w.writer, &.{}, .{ .format = format });
        try tw.add(.{ .entry = .{ .name = "a", .size = 5, .mtime = t } }, "hello");
        try tw.add(.{ .entry = .{ .name = "d/", .kind = .directory, .mtime = t } }, "");
        if (format != .ustar) {
            // A name and a link no ustar header holds: pax records, or GNU
            // long name and long link entries.
            try tw.add(.{ .entry = .{ .name = &long_name, .size = 3, .mtime = t } }, "abc");
            try tw.add(.{ .entry = .{ .name = "s", .kind = .symlink, .link = &long_link, .mtime = t } }, "");
        }
        try tw.finish();
        o.* = try w.toOwnedSlice();
    }
}

/// The limits a tar is read under: a header record of 256 bytes, which a
/// ustar name (155 + 1 + 100) and the examples' long names fit.
const tar_limits: hold.Limits = .{ .header = .fromRaw(256), .entries = .fromRaw(64), .window = .fromRaw(1 << 20) };

/// `out` made from one of `examples` as `draw` makes it, then, half the
/// time, one header's size field set to a drawn octal number and its
/// checksum written again, so that the header still reads as one.
fn drawTar(s: *shakedown.Source, out: []u8, examples: []const []const u8) []u8 {
    const bytes = draw(s, out, examples);
    if (bytes.len < 512 or !gen.boolean(s)) return bytes;
    const block = gen.intRange(s, usize, 0, bytes.len / 512 - 1) * 512;
    const h = bytes[block..][0..512];
    const sizes = [_]u64{ 0, 1, 255, 256, 257, 1000, 4096, 1 << 20, 0o77777777777 };
    _ = std.fmt.printInt(h[124..135], gen.oneOf(s, u64, &sizes), 8, .lower, .{ .width = 11, .fill = '0' });
    h[135] = 0;
    @memset(h[148..156], ' ');
    var sum: u32 = 0;
    for (h) |c| sum += c;
    _ = std.fmt.printInt(h[148..154], sum, 8, .lower, .{ .width = 6, .fill = '0' });
    h[154] = 0;
    return bytes;
}

/// One mutated tar, read forward: each header, then its contents.
fn tarOne(examples: []const []const u8, case: *shakedown.Case) anyerror!void {
    var counting: shakedown.alloc.Counting = .init(testing.allocator);
    try tarRead(examples, case, counting.allocator());
    // Nothing is allocated past what the header limit allows: an extension
    // header's data, the records merged, and the buffers around them.
    try testing.expect(counting.peak_bytes <= 64 * 1024);
}

fn tarRead(examples: []const []const u8, case: *shakedown.Case, gpa: std.mem.Allocator) anyerror!void {
    var buffer: [4096]u8 = undefined;
    const bytes = drawTar(case.source, &buffer, examples);
    var in: std.Io.Reader = .fixed(bytes);
    var tr: hold.tar.Reader = .init(gpa, &in, &.{}, .{ .limits = tar_limits });
    defer tr.deinit();
    var count: usize = 0;
    while (count < 64) : (count += 1) {
        const entry = (tr.next() catch |e| switch (e) {
            error.Invalid, error.Truncated, error.LimitExceeded => return,
            else => return e,
        }) orelse return;
        // A header's name and link are bounded by the header limit.
        try testing.expect(tar_limits.header.compare(.fromRaw(entry.name.len)) != .lt);
        try testing.expect(tar_limits.header.compare(.fromRaw(entry.link.len)) != .lt);
        const got = drain(tr.contents()) catch |e| switch (e) {
            error.ReadFailed => {
                try testing.expect(tr.err() != null);
                return;
            },
            else => return e,
        };
        // An entry gives its size, never more (a sparse entry's zeros
        // count: its size may pass the input's).
        try testing.expect(got <= entry.size);
        if (got < most_read) try testing.expectEqual(entry.size, got);
    }
}

test "any bytes made from a tar read entry by entry within their limits, or are refused" {
    const gpa = testing.allocator;
    var tars: [3][]u8 = undefined;
    try writeTars(gpa, &tars);
    defer for (tars) |t| gpa.free(t);
    const examples = [_][]const u8{ tars[0], tars[1], tars[2] };
    try shakedown.check(gpa, @as([]const []const u8, &examples), tarOne, .{ .cases = 3000 });
}
