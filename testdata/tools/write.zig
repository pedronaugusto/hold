//! Writes archives in every dialect hold writes, for the rivals' readers to
//! check (`bay interop-write`): `write <dir>` leaves <dir>/<dialect>.tar
//! and prints, for each, the manifest libarchive must read from it.
const std = @import("std");
const hold = @import("hold");

const File = struct { entry: hold.Entry, contents: []const u8 = "" };

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const dir = try std.Io.Dir.cwd().createDirPathOpen(io, args[1], .{});
    defer dir.close(io);

    var big: [300 * 1024]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(1);
    prng.random().bytes(&big);
    const long_dir = "d/" ++ rep('x', 140);
    const long_name = long_dir ++ "/" ++ rep('y', 120) ++ ".txt";
    const t: std.Io.Timestamp = .{ .nanoseconds = 1_600_000_000_500_000_000 };
    const files = [_]File{
        .{ .entry = .{ .name = "d/", .kind = .directory, .mode = 0o755, .mtime = t } },
        .{ .entry = .{ .name = "d/a.txt", .mode = 0o644, .mtime = t }, .contents = "hello\n" },
        .{ .entry = .{ .name = "d/empty", .mode = 0o600, .mtime = t } },
        .{ .entry = .{ .name = "run.sh", .mode = 0o755, .mtime = t }, .contents = "#!/bin/sh\n" },
        .{ .entry = .{ .name = "big.bin", .mode = 0o644, .mtime = t }, .contents = &big },
        .{ .entry = .{ .name = "link", .kind = .symlink, .link = "d/a.txt", .mode = 0o777, .mtime = t } },
        .{ .entry = .{ .name = "hard", .kind = .hardlink, .link = "d/a.txt", .mode = 0o644, .mtime = t } },
        .{ .entry = .{ .name = long_dir ++ "/", .kind = .directory, .mode = 0o755, .mtime = t } },
        .{ .entry = .{ .name = long_name, .mode = 0o644, .mtime = t }, .contents = "long\n" },
        .{ .entry = .{ .name = "d\u{e9}.txt", .mode = 0o644, .mtime = t }, .contents = "unicode\n" },
        .{ .entry = .{ .name = "owner", .mode = 0o644, .uid = 3_000_000, .gid = 3_000_001, .uname = "a-rather-long-user-name-past-32-bytes", .gname = "g", .mtime = t }, .contents = "x" },
        .{ .entry = .{ .name = "old", .mode = 0o644, .mtime = hold.Entry.seconds(-86400) }, .contents = "1969\n" },
    };

    var out_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buffer);
    for ([_]hold.tar.Writer.Format{ .ustar, .pax, .gnu }) |format| {
        const name = try std.fmt.allocPrint(gpa, "{s}.tar", .{@tagName(format)});
        defer gpa.free(name);
        const file = try dir.createFile(io, name, .{});
        defer file.close(io);
        var fw_buffer: [64 * 1024]u8 = undefined;
        var fw = file.writer(io, &fw_buffer);
        var tw: hold.tar.Writer = .init(&fw.interface, &.{}, .{ .format = format });
        try stdout.interface.print("== {s}\n", .{name});
        for (files) |f| {
            tw.add(.{ .entry = f.entry, .exact_times = true }, f.contents) catch |e| switch (e) {
                // ustar holds no long name, large id or negative time.
                error.Unrepresentable => continue,
                else => return e,
            };
            const e = f.entry;
            const size = if (e.kind == .file) f.contents.len else 0;
            var h: u64 = 0xcbf29ce484222325;
            if (e.kind == .file) for (f.contents) |c| {
                h = (h ^ c) *% 0x100000001b3;
            };
            try stdout.interface.print("{s} {d} {o} {d} {x:0>16} {s}\t{s}\n", .{ @tagName(e.kind), size, e.mode.?, @divFloor(e.mtime.?.nanoseconds, std.time.ns_per_s), h, e.name, e.link });
        }
        try tw.finish();
        try fw.interface.flush();
    }
    try writeZips(gpa, io, dir, &stdout.interface, &files);
    try stdout.interface.flush();
}

/// The same entries as zip: DEFLATE in memory, stored, zstd, streamed
/// with data descriptors, and with ZIP64's fields forced.
fn writeZips(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, out: *std.Io.Writer, files: []const File) !void {
    const Variant = struct { name: []const u8, method: hold.zip.Method, streamed: bool = false, zip64: hold.zip.Writer.Zip64 = .auto };
    const variants = [_]Variant{
        .{ .name = "deflate.zip", .method = .deflate },
        .{ .name = "stored.zip", .method = .stored },
        .{ .name = "zstd.zip", .method = .zstd },
        .{ .name = "streamed.zip", .method = .deflate, .streamed = true },
        .{ .name = "zip64.zip", .method = .deflate, .streamed = true, .zip64 = .always },
    };
    for (variants) |v| {
        const file = try dir.createFile(io, v.name, .{});
        defer file.close(io);
        var fw_buffer: [64 * 1024]u8 = undefined;
        var fw = file.writer(io, &fw_buffer);
        var zw: hold.zip.Writer = .init(gpa, &fw.interface, .{});
        defer zw.deinit();
        try out.print("== {s}\n", .{v.name});
        for (files) |f| {
            // zip holds no hard links or 1969 times.
            if (f.entry.kind == .hardlink or f.entry.mtime.?.nanoseconds < 0) continue;
            const h: hold.zip.Writer.Header = .{ .entry = f.entry, .method = v.method, .zip64 = v.zip64 };
            if (v.streamed and f.entry.kind == .file) {
                const w = try zw.begin(h);
                try w.writeAll(f.contents);
                try zw.end();
            } else try zw.add(h, f.contents);
            const e = f.entry;
            const size = if (e.kind == .file) f.contents.len else 0;
            var hash: u64 = 0xcbf29ce484222325;
            if (e.kind == .file) for (f.contents) |c| {
                hash = (hash ^ c) *% 0x100000001b3;
            };
            const link = if (e.kind == .symlink) e.link else "";
            try out.print("{s} {d} {o} {d} {x:0>16} {s}\t{s}\n", .{ @tagName(e.kind), size, e.mode.?, @divFloor(e.mtime.?.nanoseconds, std.time.ns_per_s), hash, e.name, link });
        }
        try zw.finish("hold");
        try fw.interface.flush();
    }
}

fn rep(comptime c: u8, comptime n: usize) [n]u8 {
    return @splat(c);
}
