//! Extraction, and the hostile-input rules (design §3) each with a test,
//! the published shapes among them.
const std = @import("std");
const hold = @import("../hold.zig");

const Item = struct { entry: hold.Entry, contents: []const u8 = "" };

fn tarOf(gpa: std.mem.Allocator, items: []const Item) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var tw: hold.tar.Writer = .init(&out.writer, &.{}, .{});
    for (items) |it| try tw.add(.{ .entry = it.entry }, it.contents);
    try tw.finish();
    return out.toOwnedSlice();
}

fn extractTar(dir: std.Io.Dir, archive: []const u8, options: hold.Extract.Options) hold.Extract.Error!hold.Extract.Summary {
    var in: std.Io.Reader = .fixed(archive);
    var tr: hold.tar.Reader = .init(std.testing.allocator, &in, &.{}, .{});
    defer tr.deinit();
    return hold.extract(std.testing.io, std.testing.allocator, dir, .{ .tar = &tr }, options);
}

fn readFile(dir: std.Io.Dir, path: []const u8, buf: []u8) ![]u8 {
    return dir.readFile(std.testing.io, path, buf);
}

test "a tree extracts: files, directories, links, times and modes" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const t = hold.Entry.seconds(1_600_000_000);
    const archive = try tarOf(gpa, &.{
        .{ .entry = .{ .name = "d/", .kind = .directory, .mode = 0o755, .mtime = t } },
        .{ .entry = .{ .name = "d/a.txt", .mode = 0o644, .mtime = t }, .contents = "hello\n" },
        .{ .entry = .{ .name = "d/run", .mode = 0o4777, .mtime = t }, .contents = "#!/bin/sh\n" },
        .{ .entry = .{ .name = "d/link", .kind = .symlink, .link = "a.txt", .mtime = t } },
        .{ .entry = .{ .name = "hard", .kind = .hardlink, .link = "d/a.txt" } },
        .{ .entry = .{ .name = "./", .kind = .directory } },
    });
    defer gpa.free(archive);
    const summary = try extractTar(tmp.dir, archive, .{});
    try std.testing.expectEqual(@as(u64, 2), summary.files);
    try std.testing.expectEqual(@as(u64, 2), summary.links);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("hello\n", try readFile(tmp.dir, "d/a.txt", &buf));
    try std.testing.expectEqualStrings("hello\n", try readFile(tmp.dir, "d/link", &buf));
    try std.testing.expectEqualStrings("hello\n", try readFile(tmp.dir, "hard", &buf));
    const st = try tmp.dir.statFile(std.testing.io, "d/a.txt", .{});
    try std.testing.expectEqual(t.nanoseconds, st.mtime.nanoseconds);
    if (@import("builtin").os.tag != .windows) {
        // The set-user-ID bit and others' write are dropped.
        const run = try tmp.dir.statFile(std.testing.io, "d/run", .{});
        try std.testing.expectEqual(@as(u32, 0o755), @as(u32, @intCast(run.permissions.toMode() & 0o7777)));
    }
}

test "Zip Slip: a name with .. is refused, nothing written outside" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "dest");
    const dest = try tmp.dir.openDir(std.testing.io, "dest", .{});
    defer dest.close(std.testing.io);
    for ([_][]const u8{ "../evil", "a/../../evil", "/tmp/evil", "a\\..\\..\\evil", "C:evil" }) |bad| {
        const archive = try tarOf(gpa, &.{.{ .entry = .{ .name = bad }, .contents = "x" }});
        defer gpa.free(archive);
        try std.testing.expectError(error.UnsafeName, extractTar(dest, archive, .{}));
    }
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "evil", .{}));
}

test "a symbolic link out of the destination is refused, by every route" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][2][]const u8{ .{ "l", "/etc" }, .{ "l", "../x" }, .{ "a/l", "../../x" }, .{ "l2", "sub/l/.." } }) |bad| {
        const archive = try tarOf(gpa, &.{.{ .entry = .{ .name = bad[0], .kind = .symlink, .link = bad[1] } }});
        defer gpa.free(archive);
        try std.testing.expectError(error.UnsafeLink, extractTar(tmp.dir, archive, .{}));
    }
    // Refused links are made with `.any_unsafe` only.
    const ok = try tarOf(gpa, &.{.{ .entry = .{ .name = "out", .kind = .symlink, .link = "../x" } }});
    defer gpa.free(ok);
    _ = try extractTar(tmp.dir, ok, .{ .links = .any_unsafe });
}

test "a write through a symbolic link is refused, the archive's or the destination's" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    try tmp.dir.createDirPath(std.testing.io, "dest");
    try tmp.dir.createDirPath(std.testing.io, "outside");
    const dest = try tmp.dir.openDir(std.testing.io, "dest", .{});
    defer dest.close(std.testing.io);
    // The destination already holds a link out (the npm tar CVE-2021-32803
    // shape): a file under it must not land outside.
    try dest.symLink(std.testing.io, "../outside", "escape", .{});
    const archive = try tarOf(gpa, &.{.{ .entry = .{ .name = "escape/f" }, .contents = "x" }});
    defer gpa.free(archive);
    try std.testing.expectError(error.ThroughLink, extractTar(dest, archive, .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "outside/f", .{}));
    // The archive makes a link inside, then writes under it: the link is
    // made last, so the file lands in a real directory, and the link is
    // refused where that directory now stands.
    const second = try tarOf(gpa, &.{
        .{ .entry = .{ .name = "in", .kind = .symlink, .link = "sub" } },
        .{ .entry = .{ .name = "in/f" }, .contents = "x" },
    });
    defer gpa.free(second);
    try std.testing.expectError(error.IsDir, extractTar(dest, second, .{}));
}

test "a hard link to anything this extraction did not write is refused" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "../../etc/passwd", "/etc/passwd", "never-written" }) |target| {
        const archive = try tarOf(gpa, &.{.{ .entry = .{ .name = "h", .kind = .hardlink, .link = target } }});
        defer gpa.free(archive);
        try std.testing.expectError(error.UnsafeLink, extractTar(tmp.dir, archive, .{}));
    }
}

test "devices and FIFOs are refused unless skipped" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const archive = try tarOf(gpa, &.{.{ .entry = .{ .name = "null", .kind = .character_device, .device = .{ .major = 1, .minor = 3 } } }});
    defer gpa.free(archive);
    try std.testing.expectError(error.Special, extractTar(tmp.dir, archive, .{}));
    const s = try extractTar(tmp.dir, archive, .{ .specials = .skip });
    try std.testing.expectEqual(@as(u64, 1), s.skipped);
}

test "the total bound stops an extraction at its limit" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const archive = try tarOf(gpa, &.{.{ .entry = .{ .name = "big" }, .contents = "0123456789" }});
    defer gpa.free(archive);
    try std.testing.expectError(error.LimitExceeded, extractTar(tmp.dir, archive, .{ .total = .fromRaw(5) }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "big", .{}));
}

test "a zip extracts through its central directory" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var zw: hold.zip.Writer = .init(gpa, &out.writer, .{});
    defer zw.deinit();
    try zw.add(.{ .entry = .{ .name = "dir/a.txt", .mtime = hold.Entry.seconds(1_600_000_000) } }, "zipped hello");
    try zw.add(.{ .entry = .{ .name = "link", .kind = .symlink, .link = "dir/a.txt" } }, "");
    try zw.finish("");
    var archive = try hold.zip.Archive.open(gpa, .{ .memory = out.written() }, .{});
    defer archive.deinit();
    const s = try hold.extract(std.testing.io, gpa, tmp.dir, .{ .zip = &archive }, .{});
    try std.testing.expectEqual(@as(u64, 1), s.files);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("zipped hello", try readFile(tmp.dir, "link", &buf));
}

test "durable extraction spans batches: every file, link and directory lands" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    // More files than three batches hold, in nested directories made on
    // the way, with links to some of them.
    const count = hold.Extract.batch_len * 3 + 5;
    for (0..count) |i| {
        const n = try gpa.print("d{d}/e{d}/f{d}", .{ i % 4, i % 3, i });
        try names.append(gpa, n);
        try items.append(gpa, .{ .entry = .{ .name = n }, .contents = n });
    }
    try items.append(gpa, .{ .entry = .{ .name = "d0/", .kind = .directory, .mode = 0o750 } });
    try items.append(gpa, .{ .entry = .{ .name = "d0/e0/soft", .kind = .symlink, .link = "f0" } });
    try items.append(gpa, .{ .entry = .{ .name = "hard", .kind = .hardlink, .link = "d1/e1/f1" } });
    const archive = try tarOf(gpa, items.items);
    defer gpa.free(archive);
    const s = try extractTar(tmp.dir, archive, .{ .level = .data });
    try std.testing.expectEqual(@as(u64, count), s.files);
    try std.testing.expectEqual(@as(u64, 2), s.links);
    var buf: [64]u8 = undefined;
    for (names.items) |n| try std.testing.expectEqualStrings(n, try readFile(tmp.dir, n, &buf));
    try std.testing.expectEqualStrings("d0/e0/f0", try readFile(tmp.dir, "d0/e0/soft", &buf));
    try std.testing.expectEqualStrings("d1/e1/f1", try readFile(tmp.dir, "hard", &buf));
}

test "a failed extraction publishes nothing of its open batch" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const archive = try tarOf(gpa, &.{
        .{ .entry = .{ .name = "first" }, .contents = "kept back" },
        .{ .entry = .{ .name = "../out" }, .contents = "refused" },
    });
    defer gpa.free(archive);
    try std.testing.expectError(error.UnsafeName, extractTar(tmp.dir, archive, .{ .level = .data }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "first", .{}));
    // No temp is left behind either.
    var it = tmp.dir.iterate();
    try std.testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(std.testing.io));
}

test "a 7z extracts, its solid folder read once in order" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const testdata = @import("testdata");
    const bytes = for (testdata.sevenz) |c| {
        if (std.mem.eql(u8, c.name, "sevenz/7zz-deflate.7z")) break c.archive;
    } else unreachable; // unreachable: the index has it
    var archive = try hold.sevenz.Archive.open(gpa, .{ .memory = bytes }, .{});
    defer archive.deinit();
    const s = try hold.extract(std.testing.io, gpa, tmp.dir, .{ .sevenz = &archive }, .{ .level = .data });
    try std.testing.expectEqual(@as(u64, 4), s.files);
    try std.testing.expectEqual(@as(u64, 1), s.links);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("hello\n", try readFile(tmp.dir, "dir/a.txt", &buf));
    try std.testing.expectEqualStrings("hello\n", try readFile(tmp.dir, "link", &buf));
}

test "more directories than stay open: each still extracts, links across them too" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    // Files round-robin over 100 directories two deep, then hard links
    // from the last directories to the first.
    for (0..300) |i| {
        const n = try gpa.print("a{d}/b/f{d}", .{ i % 100, i });
        try names.append(gpa, n);
        try items.append(gpa, .{ .entry = .{ .name = n }, .contents = n });
    }
    for (0..20) |i| {
        const n = try gpa.print("a{d}/b/h{d}", .{ 99 - i, i });
        try names.append(gpa, n);
        try items.append(gpa, .{ .entry = .{ .name = n, .kind = .hardlink, .link = names.items[i] } });
    }
    const archive = try tarOf(gpa, items.items);
    defer gpa.free(archive);
    const s = try extractTar(tmp.dir, archive, .{ .level = .data });
    try std.testing.expectEqual(@as(u64, 300), s.files);
    try std.testing.expectEqual(@as(u64, 20), s.links);
    var buf: [64]u8 = undefined;
    for (names.items[0..300]) |n| try std.testing.expectEqualStrings(n, try readFile(tmp.dir, n, &buf));
    try std.testing.expectEqualStrings(names.items[0], try readFile(tmp.dir, names.items[300], &buf));
}

test "in place, the fast mode: each file under its own name, a later entry of a name and a link there replaced, never followed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "dest");
    try tmp.dir.createDirPath(io, "outside");
    const dest = try tmp.dir.openDir(io, "dest", .{});
    defer dest.close(io);
    const links = @import("builtin").os.tag != .windows;
    // The destination holds a link out at a file's name.
    if (links) try dest.symLink(io, "../outside/f", "f", .{});
    const archive = try tarOf(gpa, &.{
        .{ .entry = .{ .name = "d/a" }, .contents = "first" },
        .{ .entry = .{ .name = "f" }, .contents = "mine" },
        .{ .entry = .{ .name = "d/a" }, .contents = "second" },
    });
    defer gpa.free(archive);
    const summary = try extractTar(dest, archive, .{ .place = .in_place });
    try std.testing.expectEqual(@as(u64, 3), summary.files);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("second", try readFile(dest, "d/a", &buf));
    try std.testing.expectEqualStrings("mine", try readFile(dest, "f", &buf));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "outside/f", .{}));
    // No temp beside the names.
    var d = try dest.openDir(io, "d", .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    try std.testing.expectEqualStrings("a", (try it.next(io)).?.name);
    try std.testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(io));
}

test "in place, a failed extraction removes the files of its open batch" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const archive = try tarOf(gpa, &.{
        .{ .entry = .{ .name = "first" }, .contents = "written in place" },
        .{ .entry = .{ .name = "../out" }, .contents = "refused" },
    });
    defer gpa.free(archive);
    try std.testing.expectError(error.UnsafeName, extractTar(tmp.dir, archive, .{ .place = .in_place }));
    var it = tmp.dir.iterate();
    try std.testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(std.testing.io));
}
