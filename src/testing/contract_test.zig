//! The README's promises held over generated archives: a tar of any
//! entries reads back as written, names past ustar's fields and times with
//! a fraction included; a zip reads back the same through its central
//! directory and forward, by every method it writes; and an extraction of
//! hostile names and links, whatever it refuses, writes nothing outside its
//! directory and leaves no link there that leads out.
const std = @import("std");
const shakedown = @import("shakedown");
const hold = @import("../hold.zig");

const testing = std.testing;
const gen = shakedown.gen;

const Drawn = struct { entry: hold.Entry, contents: []const u8 };

const sixty: [60]u8 = @splat('x');
const long: [120]u8 = @splat('y');
const parts = [_][]const u8{ "a", "b", "dir", "d\u{e9}", &sixty, &long };

/// A name of one to three parts, unique by its index; long ones need pax.
fn drawName(s: *shakedown.Source, buffer: []u8, index: usize) []const u8 {
    var len: usize = 0;
    for (0..gen.intRange(s, usize, 1, 3)) |i| {
        if (i != 0) {
            buffer[len] = '/';
            len += 1;
        }
        const part = parts[gen.intRange(s, usize, 0, parts.len - 1)];
        @memcpy(buffer[len..][0..part.len], part);
        len += part.len;
    }
    const tag = std.mem.print(buffer[len..], ".{d}", .{index}) catch unreachable; // unreachable: room is left for the tag
    return buffer[0 .. len + tag.len];
}

fn drawContents(s: *shakedown.Source, buffer: []u8) []const u8 {
    const n = gen.intRange(s, usize, 0, buffer.len);
    // Runs, so that compression has something to find, and noise.
    for (buffer[0..n], 0..) |*b, i| b.* = if (gen.boolean(s)) @intCast(i % 7 + 'a') else gen.int(s, u8);
    return buffer[0..n];
}

fn readAll(gpa: std.mem.Allocator, r: *std.Io.Reader) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = try r.streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

test "a tar of any entries reads back as written" {
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            const gpa = testing.allocator;
            const s = case.source;
            var names: [6][512]u8 = undefined;
            var bodies: [6][3000]u8 = undefined;
            var links: [6][64]u8 = undefined;
            var drawn: [6]Drawn = undefined;
            const n = gen.intRange(s, usize, 0, drawn.len);
            var out: std.Io.Writer.Allocating = .init(gpa);
            defer out.deinit();
            var tw: hold.tar.Writer = .init(&out.writer, &.{}, .{});
            for (drawn[0..n], 0..) |*d, i| {
                const name = drawName(s, &names[i], i);
                const seconds = gen.intRange(s, i64, -1_000_000_000, 4_000_000_000);
                const nanos: i96 = if (gen.boolean(s)) @as(i96, gen.intRange(s, i64, 1, 999_999_999)) else 0;
                const mtime: std.Io.Timestamp = .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s + nanos };
                const mode = gen.intRange(s, u32, 0, 0o7777);
                d.* = switch (gen.intRange(s, u8, 0, 3)) {
                    0 => .{ .entry = .{ .name = name, .kind = .directory, .mode = mode, .mtime = mtime }, .contents = "" },
                    1 => .{ .entry = .{ .name = name, .kind = .symlink, .link = std.mem.print(&links[i], "t{d}", .{gen.int(s, u16)}) catch unreachable, .mode = mode, .mtime = mtime }, .contents = "" }, // unreachable: a u16 fits
                    else => blk: {
                        const body = drawContents(s, &bodies[i]);
                        break :blk .{ .entry = .{ .name = name, .size = body.len, .mode = mode, .mtime = mtime }, .contents = body };
                    },
                };
                try tw.add(.{ .entry = d.entry, .exact_times = true }, d.contents);
            }
            try tw.finish();

            var in: std.Io.Reader = .fixed(out.written());
            var tr: hold.tar.Reader = .init(gpa, &in, &.{}, .{});
            defer tr.deinit();
            for (drawn[0..n]) |d| {
                const e = (try tr.next()) orelse return error.EntryMissing;
                try testing.expectEqualStrings(d.entry.name, e.name);
                try testing.expectEqual(d.entry.kind, e.kind);
                try testing.expectEqualStrings(d.entry.link, e.link);
                try testing.expectEqual(d.entry.mode, e.mode);
                try testing.expectEqual(d.entry.mtime.?.nanoseconds, e.mtime.?.nanoseconds);
                const got = try readAll(gpa, tr.contents());
                defer gpa.free(got);
                try testing.expectEqualSlices(u8, d.contents, got);
            }
            try testing.expectEqual(null, try tr.next());
        }
    }.one, .{ .cases = 300 });
}

test "a zip reads back as written, through its central directory and forward, by every method it writes" {
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            const gpa = testing.allocator;
            const s = case.source;
            var names: [6][512]u8 = undefined;
            var bodies: [6][3000]u8 = undefined;
            var drawn: [6]Drawn = undefined;
            // Whether the forward reader must refuse the entry: stored and
            // streamed, its CRC after it in a data descriptor, it has no end
            // to find.
            var refused: [6]bool = @splat(false);
            const n = gen.intRange(s, usize, 0, drawn.len);
            var out: std.Io.Writer.Allocating = .init(gpa);
            defer out.deinit();
            var zw: hold.zip.Writer = .init(gpa, &out.writer, .{});
            defer zw.deinit();
            const t = hold.Entry.seconds(1_600_000_000);
            for (drawn[0..n], 0..) |*d, i| {
                const body = drawContents(s, &bodies[i]);
                d.* = .{ .entry = .{ .name = drawName(s, &names[i], i), .mtime = t }, .contents = body };
                const method: hold.zip.Method = switch (gen.intRange(s, u8, 0, 2)) {
                    0 => .stored,
                    1 => .deflate,
                    else => .zstd,
                };
                if (gen.boolean(s)) {
                    try zw.add(.{ .entry = d.entry, .method = method }, body);
                } else {
                    const sized = gen.boolean(s);
                    refused[i] = method == .stored;
                    const w = try zw.begin(.{ .entry = d.entry, .method = method, .size = if (sized) body.len else null });
                    try w.writeAll(body);
                    try zw.end();
                }
            }
            try zw.finish("");

            var archive = try hold.zip.Archive.open(gpa, .{ .memory = out.written() }, .{});
            defer archive.deinit();
            try testing.expectEqual(@as(u64, n), archive.len());
            var it = archive.iterate();
            for (drawn[0..n]) |d| {
                const r = it.next() orelse return error.EntryMissing;
                try testing.expectEqualStrings(d.entry.name, r.entry.name);
                var c: hold.zip.Archive.Contents = undefined;
                try archive.contents(&c, r, &.{}, .{});
                defer c.deinit();
                const got = try readAll(gpa, c.reader());
                defer gpa.free(got);
                try testing.expectEqualSlices(u8, d.contents, got);
            }

            var in: std.Io.Reader = .fixed(out.written());
            var st: hold.zip.Stream = .init(gpa, &in, &.{}, .{});
            defer st.deinit();
            for (drawn[0..n], refused[0..n]) |d, refuse| {
                if (refuse) {
                    try testing.expectError(error.Unsupported, st.next());
                    return;
                }
                const r = (try st.next()) orelse return error.EntryMissing;
                try testing.expectEqualStrings(d.entry.name, r.entry.name);
                const got = try readAll(gpa, st.contents());
                defer gpa.free(got);
                try testing.expectEqualSlices(u8, d.contents, got);
            }
            try testing.expectEqual(null, try st.next());
        }
    }.one, .{ .cases = 300 });
}

/// Every path under `dir`, relative to it, links not followed.
fn listAll(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, into: *std.ArrayList([]u8)) !void {
    var pending: std.ArrayList([]u8) = .empty;
    defer {
        for (pending.items) |p| gpa.free(p);
        pending.deinit(gpa);
    }
    try pending.append(gpa, try gpa.dupe(u8, "."));
    while (pending.pop()) |prefix| {
        defer gpa.free(prefix);
        var sub = try dir.openDir(io, prefix, .{ .iterate = true, .follow_symlinks = false });
        defer sub.close(io);
        var it = sub.iterate();
        while (try it.next(io)) |entry| {
            const path = try std.fs.path.join(gpa, &.{ prefix, entry.name });
            errdefer gpa.free(path);
            if (entry.kind == .directory) try pending.append(gpa, try gpa.dupe(u8, path));
            try into.append(gpa, path);
        }
    }
}

/// Whether `target`, read from a link at `at` (a path relative to the
/// root), stays inside the root when resolved by its components.
fn staysInside(at: []const u8, target: []const u8) bool {
    if (std.fs.path.isAbsolute(target)) return false;
    var depth: isize = 0;
    var parent = std.mem.tokenizeScalar(u8, std.fs.path.dirname(at) orelse "", '/');
    while (parent.next()) |p| {
        if (!std.mem.eql(u8, p, ".")) depth += 1;
    }
    var it = std.mem.tokenizeScalar(u8, target, '/');
    while (it.next()) |p| {
        if (std.mem.eql(u8, p, "..")) depth -= 1 else if (!std.mem.eql(u8, p, ".")) depth += 1;
        if (depth < 0) return false;
    }
    return true;
}

const hostile_parts = [_][]const u8{ "a", "b", "..", ".", "" };
const hostile_targets = [_][]const u8{ "a", "../a", "../../outside/s", "/tmp", "b/../..", "a/b", "." };

test "an extraction of hostile names and links writes nothing outside its directory and leaves no link leading out" {
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            const gpa = testing.allocator;
            const io = testing.io;
            const s = case.source;
            var tmp = testing.tmpDir(.{ .iterate = true });
            defer tmp.cleanup();
            try tmp.dir.createDirPath(io, "root");
            try tmp.dir.createDirPath(io, "outside");
            try tmp.dir.writeFile(io, .{ .sub_path = "outside/s", .data = "kept" });
            // Links need a right not every Windows account holds.
            tmp.dir.symLink(io, "nowhere", "probe", .{}) catch return error.SkipZigTest;
            try tmp.dir.deleteFile(io, "probe");

            var names: [8][64]u8 = undefined;
            var out: std.Io.Writer.Allocating = .init(gpa);
            defer out.deinit();
            var tw: hold.tar.Writer = .init(&out.writer, &.{}, .{});
            for (0..gen.intRange(s, usize, 1, names.len)) |i| {
                var len: usize = 0;
                for (0..gen.intRange(s, usize, 1, 3)) |k| {
                    if (k != 0) {
                        names[i][len] = '/';
                        len += 1;
                    }
                    const part = hostile_parts[gen.intRange(s, usize, 0, hostile_parts.len - 1)];
                    @memcpy(names[i][len..][0..part.len], part);
                    len += part.len;
                }
                if (gen.boolean(s) and len > 0) {
                    // A leading slash: an absolute name.
                    @memmove(names[i][1 .. len + 1], names[i][0..len]);
                    names[i][0] = '/';
                    len += 1;
                }
                const name = names[i][0..len];
                const target = hostile_targets[gen.intRange(s, usize, 0, hostile_targets.len - 1)];
                const entry: hold.Entry = switch (gen.intRange(s, u8, 0, 3)) {
                    0 => .{ .name = name, .kind = .symlink, .link = target },
                    1 => .{ .name = name, .kind = .hardlink, .link = target },
                    2 => .{ .name = name, .kind = .directory },
                    else => .{ .name = name, .size = 4 },
                };
                tw.add(.{ .entry = entry }, if (entry.kind == .file) "data" else "") catch continue;
            }
            try tw.finish();

            var root = try tmp.dir.openDir(io, "root", .{});
            defer root.close(io);
            var in: std.Io.Reader = .fixed(out.written());
            var tr: hold.tar.Reader = .init(gpa, &in, &.{}, .{});
            defer tr.deinit();
            // Refused or not: what follows holds either way.
            _ = hold.extract(io, gpa, root, .{ .tar = &tr }, .{}) catch {};

            // Outside the root, nothing was made or changed.
            var top: std.ArrayList([]u8) = .empty;
            defer {
                for (top.items) |p| gpa.free(p);
                top.deinit(gpa);
            }
            var outside = try tmp.dir.openDir(io, "outside", .{ .iterate = true });
            defer outside.close(io);
            try listAll(gpa, io, outside, &top);
            try testing.expectEqual(1, top.items.len);
            var buf: [8]u8 = undefined;
            try testing.expectEqualStrings("kept", try tmp.dir.readFile(io, "outside/s", &buf));
            var count: usize = 0;
            var it = tmp.dir.iterate();
            while (try it.next(io)) |_| count += 1;
            try testing.expectEqual(2, count);

            // Inside, every link leads somewhere inside.
            var inside: std.ArrayList([]u8) = .empty;
            defer {
                for (inside.items) |p| gpa.free(p);
                inside.deinit(gpa);
            }
            var walkable = try tmp.dir.openDir(io, "root", .{ .iterate = true });
            defer walkable.close(io);
            try listAll(gpa, io, walkable, &inside);
            for (inside.items) |path| {
                var target: [std.fs.max_path_bytes]u8 = undefined;
                const len = walkable.readLink(io, path, &target) catch continue;
                errdefer std.debug.print("link {s} -> {s}\n", .{ path, target[0..len] });
                try testing.expect(staysInside(path, target[0..len]));
            }
        }
    }.one, .{ .cases = 300 });
}
