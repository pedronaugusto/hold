//! Interop: every archive the rivals' own tools wrote reads to the entries
//! and bytes libarchive 3.8.10 reads from it, line for line of its
//! manifest; an archive libarchive refuses, hold refuses after the same
//! entries.
const std = @import("std");
const hold = @import("../hold.zig");
const testdata = @import("testdata");

/// FNV-1a over 64 bits, as testdata/tools/manifest.c hashes contents.
const Fnv = struct {
    h: u64 = 0xcbf29ce484222325,
    n: u64 = 0,
    fn update(f: *Fnv, bytes: []const u8) void {
        for (bytes) |b| f.h = (f.h ^ b) *% 0x100000001b3;
        f.n += bytes.len;
    }
};

/// The contents' hash: stored runs read, holes passed over with `discard`
/// and hashed arithmetically (FNV-1a of n zeros multiplies by the prime
/// n times), so a 10 GiB sparse file costs its stored bytes.
fn hashContents(tr: *hold.tar.Reader, size: u64, fnv: *Fnv) !void {
    const r = tr.contents();
    const runs = tr.segments();
    var at: u64 = 0;
    for (runs) |run| {
        try zeros(r, fnv, run.offset - at);
        try stored(r, fnv, run.len);
        at = run.offset + run.len;
    }
    if (runs.len == 0) try stored(r, fnv, size) else try zeros(r, fnv, size - at);
    var probe: [1]u8 = undefined;
    if (try r.readSliceShort(&probe) != 0) return error.TooLong;
}

fn zeros(r: *std.Io.Reader, fnv: *Fnv, n: u64) !void {
    try r.discardAll64(n);
    var p: u64 = 0x100000001b3;
    var k = n;
    while (k != 0) : (k >>= 1) {
        if (k & 1 != 0) fnv.h *%= p;
        p *%= p;
    }
    fnv.n += n;
}

fn stored(r: *std.Io.Reader, fnv: *Fnv, n: u64) !void {
    var buf: [4096]u8 = undefined;
    var left = n;
    while (left != 0) {
        const want: usize = @intCast(@min(left, buf.len));
        try r.readSliceAll(buf[0..want]);
        fnv.update(buf[0..want]);
        left -= want;
    }
}

fn kindName(k: hold.Entry.Kind) []const u8 {
    return @tagName(k);
}

fn tarManifest(gpa: std.mem.Allocator, archive: []const u8, out: *std.Io.Writer) !void {
    var in: std.Io.Reader = .fixed(archive);
    var tr: hold.tar.Reader = .init(gpa, &in, &.{}, .{});
    defer tr.deinit();
    while (true) {
        const e = tr.next() catch |err| {
            try out.print("error {s}\n", .{@errorName(err)});
            return;
        } orelse return;
        var fnv: Fnv = .{};
        hashContents(&tr, e.size, &fnv) catch {
            try out.print("error {s}\n", .{@errorName(tr.err() orelse error.ReadFailed)});
            return;
        };
        const secs = @divFloor(e.mtime.?.nanoseconds, std.time.ns_per_s);
        try out.print("{s} {d} {o} {d} {x:0>16} {s}\t{s}\n", .{ kindName(e.kind), fnv.n, e.mode orelse 0, secs, fnv.h, e.name, e.link });
    }
}

test "tar: the rivals' archives read as libarchive reads them" {
    const gpa = std.testing.allocator;
    var failures: usize = 0;
    for (testdata.tar) |case| {
        var got: std.Io.Writer.Allocating = .init(gpa);
        defer got.deinit();
        try tarManifest(gpa, case.archive, &got.writer);
        if (!sameManifest(case.manifest, got.written())) {
            failures += 1;
            std.debug.print("\n== {s}\n-- libarchive\n{s}-- hold\n{s}", .{ case.name, case.manifest, got.written() });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}

/// Line for line; an error line matches any error line, the two readers
/// naming their errors differently, and a `.hold` file's `# ` lines say
/// why it differs from libarchive's.
fn sameManifest(want: []const u8, got: []const u8) bool {
    var a = std.mem.splitScalar(u8, want, '\n');
    var b = std.mem.splitScalar(u8, got, '\n');
    while (true) {
        var x = a.next();
        while (x != null and std.mem.startsWith(u8, x.?, "# ")) x = a.next();
        const y = b.next();
        if (x == null or y == null) return x == null and y == null;
        if (std.mem.startsWith(u8, x.?, "error ") and std.mem.startsWith(u8, y.?, "error ")) continue;
        if (!std.mem.eql(u8, x.?, y.?)) return false;
    }
}
