//! relic's `git archive` writes through hold: hold's writers, given the
//! entries git writes and git's spelling of each choice, must give git's
//! bytes (testdata/git/make.sh, git 2.56.0).
const std = @import("std");
const hold = @import("../hold.zig");
const testdata = @import("testdata");

/// `n` of `c`.
fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const bytes: [n]u8 = @splat(c);
    return &bytes;
}

const commit = "092a77f73946eea119f48848faf33f5f2886c06b";
const time = hold.Entry.seconds(1577934245);
const deep = rep('d', 60) ++ "/" ++ rep('e', 60);

/// One entry as git archives it: its mode after `tar.umask` (002) and the
/// object id git names its pax header and `.data` fallback after.
const Git = struct { name: []const u8, kind: hold.Entry.Kind = .file, mode: u32, oid: []const u8 = "", contents: []const u8 = "", link: []const u8 = "" };

const entries = [_]Git{
    .{ .name = "README", .mode = 0o664, .contents = "hello\n" },
    .{ .name = rep('d', 60) ++ "/", .kind = .directory, .mode = 0o775 },
    .{ .name = deep ++ "/", .kind = .directory, .mode = 0o775 },
    .{ .name = deep ++ "/" ++ rep('f', 60) ++ ".txt", .mode = 0o664, .contents = "deep\n" },
    .{ .name = "dir/", .kind = .directory, .mode = 0o775 },
    .{ .name = "dir/file", .mode = 0o664, .contents = "in a directory\n" },
    .{ .name = "link", .kind = .symlink, .mode = 0o777, .link = "dir/file" },
    .{ .name = "longlink", .kind = .symlink, .mode = 0o777, .oid = "176f6bd6f55a069de8f3f1d373d26ef838c1f2fd", .link = rep('t', 110) },
    .{ .name = rep('n', 120), .mode = 0o664, .oid = "2988452a618dc8ba3eff0d4db49454d7031253bb", .contents = "long\n" },
    .{ .name = "run.sh", .mode = 0o775, .contents = "#!/bin/sh\necho x\n" },
};

test "git's tar, byte for byte" {
    const gpa = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var tw: hold.tar.Writer = .init(&out.writer, &.{}, .{ .format = .pax, .checksum = .nul, .ustar_prefix = 154 });
    const root: hold.Entry = .{ .name = "", .mtime = time, .uid = 0, .gid = 0, .uname = "root", .gname = "root" };
    var global = root;
    global.name = "pax_global_header";
    try tw.global(.{ .entry = global, .pax_mode = 0o666, .records = &.{.{ .key = "comment", .value = commit }} });
    var names: [3][64]u8 = undefined;
    for (entries) |g| {
        var e = root;
        e.name = g.name;
        e.kind = g.kind;
        e.mode = g.mode;
        e.size = g.contents.len;
        e.link = g.link;
        const pax_name = try std.mem.print(&names[0], "{s}.paxheader", .{g.oid});
        const data_name = try std.mem.print(&names[1], "{s}.data", .{g.oid});
        const see = try std.mem.print(&names[2], "see {s}.paxheader", .{g.oid});
        try tw.add(.{
            .entry = e,
            .pax_name = pax_name,
            .pax_mode = 0o666,
            .ustar_name = if (g.kind == .file) data_name else null,
            .ustar_link = if (g.kind == .symlink) see else null,
        }, g.contents);
    }
    try tw.finish();
    try std.testing.expectEqualSlices(u8, testdata.git.tar, out.written());
}

test "git's stored zip, byte for byte" {
    const gpa = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var zw: hold.zip.Writer = .init(gpa, &out.writer, .{});
    defer zw.deinit();
    for (entries) |g| {
        // git's modes before `tar.umask`: what its zip records.
        const mode: u32 = switch (g.kind) {
            .symlink => 0o120777,
            else => if (g.mode & 0o100 != 0 and g.kind == .file) 0o100755 else 0,
        };
        try zw.add(.{
            .entry = .{ .name = g.name, .kind = g.kind, .mode = g.mode, .mtime = time, .link = g.link },
            .method = .stored,
            .made_by = if (mode != 0) 0x0317 else 0,
            .needed = 10,
            // git's text flag: every file here is text, and a link too.
            .internal = if (g.kind == .directory) 0 else 1,
            .external = if (g.kind == .directory) 0x10 else mode << 16,
            .dos = .{ .date = 0x5022, .time = 0x1882 },
            .utf8 = false,
        }, g.contents);
    }
    try zw.finish(commit);
    try std.testing.expectEqualSlices(u8, testdata.git.zip_store, out.written());
}
