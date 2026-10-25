//! Writes testdata/testdata.zig, the index the interop tests embed: each
//! archive with its `.hold` manifest where there is one, else libarchive's.
//! `bay testdata-index` runs it; run it after adding an archive or a
//! `.hold` file, or deleting one.
const std = @import("std");
const Io = std.Io;

const header =
    \\//! Archives other tools wrote, embedded for the interop tests, each with
    \\//! the manifest libarchive 3.8.9 reads from it, or, where hold reads it
    \\//! otherwise on purpose, the manifest hold reads and why (`.hold`).
    \\//! testdata/README.md says where each came from. Written by
    \\//! tools/index.zig (`bay testdata-index`).
    \\
    \\pub const Case = struct { name: []const u8, archive: []const u8, manifest: []const u8 };
    \\
;

const footer =
    \\
    \\/// git's own archives of one tree (git 2.56.0): hold's writers must give
    \\/// them byte for byte.
    \\pub const git = struct {
    \\    pub const tar = @embedFile("git/tree.tar");
    \\    pub const zip_store = @embedFile("git/tree-store.zip");
    \\};
    \\
;

/// Each block: its name and the directories and suffixes of its archives.
const blocks = [_]struct { name: []const u8, sets: []const [2][]const u8 }{
    .{ .name = "tar", .sets = &.{ .{ "libarchive", ".tar" }, .{ "tar", ".tar" } } },
    .{ .name = "zip", .sets = &.{ .{ "libarchive", ".zip" }, .{ "libarchive", ".zipx" }, .{ "zip", ".zip" } } },
    .{ .name = "sevenz", .sets = &.{ .{ "libarchive", ".7z" }, .{ "sevenz", ".7z" } } },
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 2) return error.TestdataDirRequired;
    const testdata = try Io.Dir.cwd().openDir(io, args[1], .{});
    defer testdata.close(io);

    var out: Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    try w.writeAll(header);
    for (blocks) |block| {
        var names: std.ArrayList([]const u8) = .empty;
        for (block.sets) |set| {
            var dir = testdata.openDir(io, set[0], .{ .iterate = true }) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            defer dir.close(io);
            var it = dir.iterate();
            while (try it.next(io)) |entry| {
                if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, set[1])) continue;
                try names.append(a, try std.mem.concat(a, u8, &.{ set[0], "/", entry.name }));
            }
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn less(_: void, x: []const u8, y: []const u8) bool {
                return std.mem.lessThan(u8, x, y);
            }
        }.less);
        try w.print("\npub const {s} = [_]Case{{\n", .{block.name});
        for (names.items) |name| {
            const hold_manifest = try std.mem.concat(a, u8, &.{ name, ".hold" });
            const has_hold = if (testdata.access(io, hold_manifest, .{})) true else |err| switch (err) {
                error.FileNotFound => false,
                else => return err,
            };
            const manifest = if (has_hold) hold_manifest else try std.mem.concat(a, u8, &.{ name, ".manifest" });
            try w.print("    .{{ .name = \"{s}\", .archive = @embedFile(\"{s}\"), .manifest = @embedFile(\"{s}\") }},\n", .{ name, name, manifest });
        }
        try w.writeAll("};\n");
    }
    try w.writeAll(footer);
    try testdata.writeFile(io, .{ .sub_path = "testdata.zig", .data = out.written() });
}
