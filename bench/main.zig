//! hold's benchmarks, measured through shakedown: reading and writing tar,
//! zip and 7z over two trees, `tree` (2,000 text files of 1 to 20 KiB, a
//! source tree's shape) and `large` (two 8 MiB files, text and random).
//! Rows are `format/operation/tree`; each unit is one whole archive.
//!
//!   hold-bench [--smoke] [--row <prefix>] [--corpus <dir>] [--emit <dir>]
//!
//! `--emit <dir>` writes the trees as files and stops, for other tools to
//! archive and other harnesses to time the same rows. `--corpus <dir>` reads
//! those archives, so every reader reads the same bytes; without it the
//! read rows read the archives hold writes, and 7z, which hold does not
//! write, is left out. `bay bench` runs it; CI runs each row once.
const std = @import("std");
const Io = std.Io;
const aegis = @import("aegis");
const hold = @import("hold");
const shakedown = @import("shakedown");
const provenance = @import("preflight_bench_options");

const Error = std.mem.Allocator.Error || Io.Writer.Error || Io.Reader.Error || hold.tar.Reader.NextError ||
    hold.tar.Writer.BeginError || hold.tar.Writer.EndError || hold.tar.Writer.ContentsError || hold.tar.Writer.FinishError ||
    hold.zip.Archive.OpenError || hold.zip.Archive.ContentsError || hold.zip.Writer.BeginError || hold.zip.Writer.EndError ||
    hold.sevenz.Archive.OpenError || hold.sevenz.Archive.ContentsError || hold.Extract.Error ||
    Io.Dir.CreateDirPathOpenError || Io.Dir.DeleteTreeError || error{ WrongLength, EntryOpen };

/// One tree: its files' names and contents, in order.
const Tree = struct {
    name: []const u8,
    names: []const []const u8,
    files: []const []const u8,
    total: u64,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var corpus: ?[]const u8 = null;
    var emit: ?[]const u8 = null;
    var rest: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--corpus") and i + 1 < args.len) {
            i += 1;
            corpus = args[i];
        } else if (std.mem.eql(u8, args[i], "--emit") and i + 1 < args.len) {
            i += 1;
            emit = args[i];
        } else try rest.append(init.arena.allocator(), args[i]);
    }
    const options = try shakedown.bench.Options.fromArguments(rest.items);
    var s: Session = .{ .gpa = init.gpa, .arena = init.arena.allocator(), .io = init.io, .options = options, .corpus = corpus };
    s.options.samples = 11;
    const trees = [_]Tree{ try s.tree("tree"), try s.tree("large") };
    if (emit) |dir| return s.emitTrees(dir, &trees);
    var buffer: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(init.io, &buffer);
    s.out = &stdout.interface;
    for (&trees) |*t| try s.rows(t);
    try stdout.interface.flush();
}

const Session = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer = undefined,
    options: shakedown.bench.Options,
    corpus: ?[]const u8,

    /// A tree, made the same way on every run: text from a fixed seed.
    fn tree(s: *Session, comptime which: []const u8) !Tree {
        const small = s.options.smoke;
        var prng: std.Random.DefaultPrng = .init(7);
        const r = prng.random();
        var names: std.ArrayList([]const u8) = .empty;
        var files: std.ArrayList([]const u8) = .empty;
        var total: u64 = 0;
        if (comptime std.mem.eql(u8, which, "tree")) {
            const count: usize = if (small) 20 else 2000;
            for (0..count) |n| {
                try names.append(s.arena, try s.arena.print("src/d{d}/f{d}.txt", .{ n % 40, n }));
                const f = try text(s.arena, r, 1024 + r.uintLessThan(usize, 19 * 1024));
                try files.append(s.arena, f);
                total += f.len;
            }
        } else {
            const size: usize = if (small) 64 * 1024 else 8 << 20;
            try names.append(s.arena, "large/text.txt");
            try files.append(s.arena, try text(s.arena, r, size));
            try names.append(s.arena, "large/random.bin");
            const bin = try s.arena.alloc(u8, size);
            r.bytes(bin);
            try files.append(s.arena, bin);
            total = 2 * size;
        }
        return .{ .name = which, .names = names.items, .files = files.items, .total = total };
    }

    fn emitTrees(s: *Session, dir: []const u8, trees: []const Tree) !void {
        const root = try Io.Dir.cwd().createDirPathOpen(s.io, dir, .{});
        defer root.close(s.io);
        for (trees) |t| for (t.names, t.files) |n, f| {
            const path = try s.arena.print("{s}/{s}", .{ t.name, n });
            if (std.fs.path.dirname(path)) |d| try root.createDirPath(s.io, d);
            try root.writeFile(s.io, .{ .sub_path = path, .data = f });
        };
    }

    /// An archive of the corpus, or null without one.
    fn archive(s: *Session, comptime format: []const u8, t: *const Tree) !?[]const u8 {
        const dir = s.corpus orelse return null;
        const path = try s.arena.print("{s}/{s}{s}", .{ dir, t.name, format });
        // A corpus archive is a few hundred MiB at most.
        return try aegis.own.readFile(s.io, Io.Dir.cwd(), path, s.arena, .fromRaw(1 << 30));
    }

    fn rows(s: *Session, t: *const Tree) !void {
        const tar_bytes = try s.archive(".tar", t) orelse try writeTar(s.arena, t);
        const zip_bytes = try s.archive("-deflate.zip", t) orelse try writeZip(s.arena, t, .deflate);
        const store_bytes = try s.archive("-store.zip", t) orelse try writeZip(s.arena, t, .stored);
        try s.measure("tar/read/{s}", t, tar_bytes, .tar_read);
        try s.measure("tar/write/{s}", t, tar_bytes, .tar_write);
        try s.measure("zip/read-deflate/{s}", t, zip_bytes, .zip_read);
        try s.measure("zip/read-store/{s}", t, store_bytes, .zip_read);
        try s.measure("zip/write-deflate/{s}", t, zip_bytes, .zip_write_deflate);
        try s.measure("zip/write-store/{s}", t, store_bytes, .zip_write_store);
        if (try s.archive("-deflate.7z", t)) |b| try s.measure("7z/read-deflate/{s}", t, b, .sevenz_read);
        try s.extractRow(t, tar_bytes);
    }

    /// Extraction of the tar into a fresh directory each unit, at
    /// `.none` as libarchive's defaults; the directory is removed after
    /// each, untimed.
    fn extractRow(s: *Session, t: *const Tree, bytes: []const u8) !void {
        const ctx = try s.arena.create(Context);
        const place = try s.arena.print("{s}/extract-tmp", .{s.corpus orelse "."});
        ctx.* = .{ .gpa = s.gpa, .tree = t, .archive = bytes, .op = .extract, .io = s.io, .place = place };
        const row: shakedown.bench.Row(Context, Error) = .{
            .name = try s.arena.print("extract/tar/{s}", .{t.name}),
            .unit = "archive",
            .grow = false,
            .run = Context.run,
            .settle = Context.settle,
            .fixture = .{ .lifetime = .row, .setup = Context.setup, .teardown = Context.teardown },
        };
        try shakedown.bench.run(Error, s.gpa, s.io, s.out, ctx, &.{row}, .{
            .commit = provenance.commit,
            .cpu = provenance.cpu,
            .os = provenance.os,
        }, s.options);
    }

    fn measure(s: *Session, comptime name: []const u8, t: *const Tree, bytes: []const u8, op: Op) !void {
        const ctx = try s.arena.create(Context);
        ctx.* = .{ .gpa = s.gpa, .tree = t, .archive = bytes, .op = op };
        const row: shakedown.bench.Row(Context, Error) = .{
            .name = try s.arena.print(name, .{t.name}),
            .unit = "archive",
            .run = Context.run,
            .fixture = .{ .lifetime = .row, .setup = Context.setup, .teardown = Context.teardown },
        };
        try shakedown.bench.run(Error, s.gpa, s.io, s.out, ctx, &.{row}, .{
            .commit = provenance.commit,
            .cpu = provenance.cpu,
            .os = provenance.os,
        }, s.options);
    }
};

const Op = enum { tar_read, tar_write, zip_read, zip_write_deflate, zip_write_store, sevenz_read, extract };

/// One row: its tree, the archive it reads, and an output buffer the
/// writing rows fill again each unit.
const Context = struct {
    gpa: std.mem.Allocator,
    tree: *const Tree,
    archive: []const u8,
    op: Op,
    out: []u8 = &.{},
    scratch: []u8 = &.{},
    /// Extraction: where each unit's directory goes.
    io: Io = undefined,
    place: []const u8 = "",

    fn setup(c: *Context) Error!void {
        c.out = try c.gpa.alloc(u8, c.tree.total + c.tree.total / 4 + (1 << 20));
        c.scratch = try c.gpa.alloc(u8, 64 * 1024);
    }

    fn teardown(c: *Context) Error!void {
        c.gpa.free(c.out);
        c.gpa.free(c.scratch);
    }

    fn run(c: *Context, units: u64) Error!void {
        for (0..units) |_| switch (c.op) {
            .tar_read => try c.tarRead(),
            .tar_write => _ = try tarInto(c.out, c.tree),
            .zip_read => try c.zipRead(),
            .zip_write_deflate => _ = try zipInto(c.gpa, c.out, c.tree, .deflate),
            .zip_write_store => _ = try zipInto(c.gpa, c.out, c.tree, .stored),
            .sevenz_read => try c.sevenzRead(),
            .extract => try c.extract(),
        };
    }

    fn extract(c: *Context) Error!void {
        var dir = try Io.Dir.cwd().createDirPathOpen(c.io, c.place, .{});
        defer dir.close(c.io);
        var in: Io.Reader = .fixed(c.archive);
        var tr: hold.tar.Reader = .init(c.gpa, &in, &.{}, .{});
        defer tr.deinit();
        const summary = try hold.extract(c.io, c.gpa, dir, .{ .tar = &tr }, .{});
        if (summary.bytes != c.tree.total) return error.WrongLength;
    }

    fn settle(c: *Context, units: u64) Error!void {
        _ = units;
        try Io.Dir.cwd().deleteTree(c.io, c.place);
    }

    /// Every entry's contents read, as an extraction reads them.
    fn tarRead(c: *Context) Error!void {
        var in: Io.Reader = .fixed(c.archive);
        var tr: hold.tar.Reader = .init(c.gpa, &in, &.{}, .{});
        defer tr.deinit();
        var total: u64 = 0;
        while (try tr.next()) |_| total += try c.drain(tr.contents());
        if (total != c.tree.total) return error.WrongLength;
    }

    fn zipRead(c: *Context) Error!void {
        var a = try hold.zip.Archive.open(c.gpa, .{ .memory = c.archive }, .{});
        defer a.deinit();
        var it = a.iterate();
        var total: u64 = 0;
        while (it.next()) |r| {
            var contents: hold.zip.Archive.Contents = undefined;
            try a.contents(&contents, r, &.{}, .{});
            defer contents.deinit();
            total += try c.drain(contents.reader());
        }
        if (total != c.tree.total) return error.WrongLength;
    }

    fn sevenzRead(c: *Context) Error!void {
        var a = try hold.sevenz.Archive.open(c.gpa, .{ .memory = c.archive }, .{});
        defer a.deinit();
        var total: u64 = 0;
        for (a.entries()) |item| total += try c.drain(try a.contents(item, &.{}));
        if (total != c.tree.total) return error.WrongLength;
    }

    /// The contents copied out, a buffer at a time, as libarchive's
    /// `archive_read_data` and Go's `io.Copy` hand them over.
    fn drain(c: *Context, r: *Io.Reader) Error!u64 {
        var total: u64 = 0;
        while (true) {
            const n = try r.readSliceShort(c.scratch);
            total += n;
            if (n < c.scratch.len) return total;
        }
    }
};

fn text(arena: std.mem.Allocator, r: std.Random, n: usize) ![]u8 {
    const words = [_][]const u8{ "const", "return", "archive", "entry", "the", "and", "error", "reader", "writer", "bytes", "if", "for", "while", "try", "hold", "name", "size", "=", "{", "}", "(", ")", ";", "\n", "    " };
    const out = try arena.alloc(u8, n);
    var at: usize = 0;
    while (at < n) {
        const w = words[r.uintLessThan(usize, words.len)];
        const k = @min(w.len, n - at);
        @memcpy(out[at..][0..k], w[0..k]);
        at += k;
        if (at < n) {
            out[at] = ' ';
            at += 1;
        }
    }
    return out;
}

fn tarInto(out: []u8, t: *const Tree) Error![]u8 {
    var w: Io.Writer = .fixed(out);
    var tw: hold.tar.Writer = .init(&w, &.{}, .{});
    for (t.names, t.files) |n, f| try tw.add(.{ .entry = .{ .name = n, .mode = 0o644, .size = f.len } }, f);
    try tw.finish();
    return w.buffered();
}

fn writeTar(arena: std.mem.Allocator, t: *const Tree) Error![]const u8 {
    const out = try arena.alloc(u8, t.total + t.total / 4 + (1 << 20));
    return tarInto(out, t);
}

fn zipInto(gpa: std.mem.Allocator, out: []u8, t: *const Tree, method: hold.zip.Method) Error![]u8 {
    var w: Io.Writer = .fixed(out);
    var zw: hold.zip.Writer = .init(gpa, &w, .{});
    defer zw.deinit();
    for (t.names, t.files) |n, f| try zw.add(.{ .entry = .{ .name = n, .mode = 0o644 }, .method = method, .level = 6 }, f);
    try zw.finish("");
    return w.buffered();
}

fn writeZip(arena: std.mem.Allocator, t: *const Tree, method: hold.zip.Method) Error![]const u8 {
    const out = try arena.alloc(u8, t.total + t.total / 4 + (1 << 20));
    return zipInto(arena, out, t, method);
}
