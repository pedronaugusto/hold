//! 7z's header, parsed from its bytes held whole (7-Zip's `7zFormat.txt`
//! and `7zIn.cpp`): the streams (packed streams, folders of coders, the
//! entries' substreams) and the files. Every count is checked against the
//! bytes that remain before anything is allocated for it.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../Limits.zig");

pub const signature = "7z\xbc\xaf\x27\x1c";
/// The signature header: signature, version, its CRC, and where the
/// header is.
pub const start_len = 32;

/// Property IDs.
pub const id = struct {
    pub const end = 0x00;
    pub const header = 0x01;
    pub const archive_properties = 0x02;
    pub const additional_streams = 0x03;
    pub const main_streams = 0x04;
    pub const files_info = 0x05;
    pub const pack_info = 0x06;
    pub const unpack_info = 0x07;
    pub const substreams_info = 0x08;
    pub const size = 0x09;
    pub const crc = 0x0a;
    pub const folder = 0x0b;
    pub const coders_unpack_size = 0x0c;
    pub const num_unpack_stream = 0x0d;
    pub const empty_stream = 0x0e;
    pub const empty_file = 0x0f;
    pub const anti = 0x10;
    pub const name = 0x11;
    pub const ctime = 0x12;
    pub const atime = 0x13;
    pub const mtime = 0x14;
    pub const attributes = 0x15;
    pub const encoded_header = 0x17;
    pub const dummy = 0x19;
};

/// The start header: where the next header is, its length and CRC.
pub const Start = struct {
    offset: u64,
    len: u64,
    crc: u32,
};

pub const StartError = error{
    /// Not a 7z signature, a major version past 0, or the start header's
    /// own CRC wrong.
    Invalid,
};

pub fn parseStart(bytes: *const [start_len]u8) StartError!Start {
    if (!std.mem.eql(u8, bytes[0..6], signature)) return error.Invalid;
    if (bytes[6] != 0) return error.Invalid;
    const crc = std.mem.readInt(u32, bytes[8..12], .little);
    if (@import("warp").crc32(0, bytes[12..32]) != crc) return error.Invalid;
    return .{
        .offset = std.mem.readInt(u64, bytes[12..20], .little),
        .len = std.mem.readInt(u64, bytes[20..28], .little),
        .crc = std.mem.readInt(u32, bytes[28..32], .little),
    };
}

pub const Coder = struct {
    /// The method, big-endian as the archive spells it.
    id: u64,
    props: []const u8,
    ins: u32 = 1,
    outs: u32 = 1,
};

/// An in-stream of one coder fed by an out-stream of another, both
/// numbered across the folder.
pub const Bind = struct { in: u32, out: u32 };

pub const Folder = struct {
    coders: []const Coder,
    binds: []const Bind,
    /// The folder in-streams the packed streams feed, in pack order.
    packed_ins: []const u32,
    /// Each out-stream's unpacked size.
    sizes: []const u64 = &.{},
    crc: ?u32 = null,
    /// Its first packed stream, in `Streams.pack_sizes`.
    first_pack: u32 = 0,
    /// Its entries' substreams, and the first of them in
    /// `Streams.stream_sizes`.
    streams: u32 = 1,
    first_stream: u32 = 0,

    /// The out-stream no bind pair consumes: the folder's output.
    pub fn mainOut(f: *const Folder) u32 {
        var total: u32 = 0;
        for (f.coders) |c| total += c.outs;
        var o: u32 = 0;
        while (o < total) : (o += 1) {
            for (f.binds) |b| {
                if (b.out == o) break;
            } else return o;
        }
        unreachable; // unreachable: `parseFolder` checked one out-stream is unbound
    }

    pub fn size(f: *const Folder) u64 {
        return f.sizes[f.mainOut()];
    }
};

pub const Streams = struct {
    /// Where the packed streams start, after the start header.
    pack_pos: u64 = 0,
    pack_sizes: []const u64 = &.{},
    folders: []Folder = &.{},
    /// Every folder's substreams in order: an entry with contents is one.
    stream_sizes: []const u64 = &.{},
    stream_crcs: []const ?u32 = &.{},
};

pub const File = struct {
    /// UTF-16LE, without its terminator.
    name: []const u8 = "",
    stream: bool = true,
    /// For an entry without a stream: a file (true) or a directory.
    empty_file: bool = false,
    /// An entry an update deletes.
    anti: bool = false,
    attributes: ?u32 = null,
    /// FILETIME: 100 ns since 1601.
    mtime: ?u64 = null,
    atime: ?u64 = null,
    ctime: ?u64 = null,
};

pub const Header = struct {
    streams: Streams = .{},
    files: []File = &.{},
};

pub const Error = error{
    /// A record or count that breaks the format, or a header that ends
    /// inside a record.
    Invalid,
    /// Additional streams or external data, which no writer produces.
    Unsupported,
    /// More entries than `Limits.entries`.
    LimitExceeded,
    OutOfMemory,
};

/// 7-Zip's own bounds on a folder: coders and their streams.
const max_coders = 64;
const max_streams = 64;

/// The header's bytes, read in order. `at` is where a refusal was.
pub const Parser = struct {
    arena: Allocator,
    bytes: []const u8,
    at: usize = 0,
    limits: Limits,

    pub fn byte(p: *Parser) Error!u8 {
        if (p.at >= p.bytes.len) return error.Invalid;
        p.at += 1;
        return p.bytes[p.at - 1];
    }

    pub fn take(p: *Parser, n: u64) Error![]const u8 {
        if (n > p.bytes.len - p.at) return error.Invalid;
        const s = p.bytes[p.at..][0..@intCast(n)];
        p.at += @intCast(n);
        return s;
    }

    fn int(p: *Parser, comptime T: type) Error!T {
        const s = try p.take(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }

    /// 7z's number: the first byte's leading ones count the bytes that
    /// follow, little-endian, and its remaining bits are the top.
    pub fn number(p: *Parser) Error!u64 {
        const first = try p.byte();
        var mask: u8 = 0x80;
        var value: u64 = 0;
        var i: u6 = 0;
        while (i < 8) : (i += 1) {
            if (first & mask == 0) {
                const high: u64 = first & (mask -% 1);
                return value | (high << (8 * i));
            }
            value |= @as(u64, try p.byte()) << (8 * i);
            mask >>= 1;
        }
        return value;
    }

    /// A number that counts things, each taking at least `each` bits of
    /// what remains: past that, the header cannot hold them.
    fn count(p: *Parser, each_bits: u64) Error!u32 {
        const n = try p.number();
        if (n > (p.bytes.len - p.at) * 8 / each_bits) return error.Invalid;
        return @intCast(n);
    }

    fn expect(p: *Parser, want: u64) Error!void {
        if (try p.number() != want) return error.Invalid;
    }

    fn bools(p: *Parser, n: usize) Error![]bool {
        if (n > (p.bytes.len - p.at) * 8) return error.Invalid;
        const out = try p.arena.alloc(bool, n);
        var b: u8 = 0;
        for (out, 0..) |*v, i| {
            if (i % 8 == 0) b = try p.byte();
            v.* = b & (@as(u8, 0x80) >> @intCast(i % 8)) != 0;
        }
        return out;
    }

    /// A vector led by an "all defined" byte.
    fn defined(p: *Parser, n: usize) Error![]bool {
        if (try p.byte() != 0) {
            const out = try p.arena.alloc(bool, n);
            @memset(out, true);
            return out;
        }
        return p.bools(n);
    }

    fn digests(p: *Parser, n: usize) Error![]?u32 {
        const which = try p.defined(n);
        const out = try p.arena.alloc(?u32, n);
        for (out, which) |*d, has| d.* = if (has) try p.int(u32) else null;
        return out;
    }

    fn skipData(p: *Parser) Error!void {
        _ = try p.take(try p.number());
    }

    // -----------------------------------------------------------------
    // Streams

    /// PackInfo, UnpackInfo and SubStreamsInfo, after `main_streams` or
    /// `encoded_header`.
    pub fn streams(p: *Parser) Error!Streams {
        var s: Streams = .{};
        var t = try p.number();
        if (t == id.pack_info) {
            try p.packInfo(&s);
            t = try p.number();
        }
        if (t == id.unpack_info) {
            try p.unpackInfo(&s);
            t = try p.number();
        }
        try checkFolders(&s);
        if (t == id.substreams_info) {
            try p.substreams(&s);
            t = try p.number();
        } else try p.defaultSubstreams(&s);
        if (t != id.end) return error.Invalid;
        return s;
    }

    fn packInfo(p: *Parser, s: *Streams) Error!void {
        s.pack_pos = try p.number();
        const n = try p.count(8);
        const sizes = try p.arena.alloc(u64, n);
        @memset(sizes, 0);
        var t = try p.number();
        if (t == id.size) {
            for (sizes) |*v| v.* = try p.number();
            t = try p.number();
        }
        if (t == id.crc) {
            _ = try p.digests(n);
            t = try p.number();
        }
        if (t != id.end) return error.Invalid;
        s.pack_sizes = sizes;
    }

    fn unpackInfo(p: *Parser, s: *Streams) Error!void {
        try p.expect(id.folder);
        const n = try p.count(8);
        if (try p.byte() != 0) return error.Unsupported;
        const folders = try p.arena.alloc(Folder, n);
        var pack: u64 = 0;
        for (folders) |*f| {
            f.* = try p.folder();
            f.first_pack = std.math.cast(u32, pack) orelse return error.Invalid;
            pack += f.packed_ins.len;
        }
        if (pack != s.pack_sizes.len) return error.Invalid;
        try p.expect(id.coders_unpack_size);
        for (folders) |*f| {
            var outs: usize = 0;
            for (f.coders) |c| outs += c.outs;
            const sizes = try p.arena.alloc(u64, outs);
            for (sizes) |*v| v.* = try p.number();
            f.sizes = sizes;
        }
        var t = try p.number();
        if (t == id.crc) {
            const crcs = try p.digests(n);
            for (folders, crcs) |*f, c| f.crc = c;
            t = try p.number();
        }
        if (t != id.end) return error.Invalid;
        s.folders = folders;
    }

    /// A folder: its coders, the bind pairs between them, and which
    /// in-streams the packed streams feed.
    fn folder(p: *Parser) Error!Folder {
        const n = try p.number();
        if (n == 0 or n > max_coders) return error.Invalid;
        const coders = try p.arena.alloc(Coder, @intCast(n));
        var ins: u32 = 0;
        var outs: u32 = 0;
        for (coders) |*c| {
            const flags = try p.byte();
            // 0x80: alternative methods, which 7-Zip never wrote.
            if (flags & 0x80 != 0) return error.Unsupported;
            const id_len = flags & 0x0f;
            if (id_len > 8) return error.Invalid;
            var method: u64 = 0;
            for (try p.take(id_len)) |b| method = (method << 8) | b;
            c.* = .{ .id = method, .props = "" };
            if (flags & 0x10 != 0) {
                const i = try p.number();
                const o = try p.number();
                if (i > max_streams or o > max_streams) return error.Invalid;
                c.ins = @intCast(i);
                c.outs = @intCast(o);
            }
            if (flags & 0x20 != 0) c.props = try p.take(try p.number());
            ins += c.ins;
            outs += c.outs;
        }
        if (outs == 0 or ins < outs - 1) return error.Invalid;
        const binds = try p.arena.alloc(Bind, outs - 1);
        for (binds) |*b| {
            const i = try p.number();
            const o = try p.number();
            if (i >= ins or o >= outs) return error.Invalid;
            b.* = .{ .in = @intCast(i), .out = @intCast(o) };
        }
        // Each in-stream and out-stream bound at most once.
        for (binds, 0..) |b, i| for (binds[i + 1 ..]) |c| {
            if (b.in == c.in or b.out == c.out) return error.Invalid;
        };
        const packed_count = ins - (outs - 1);
        const packed_ins = try p.arena.alloc(u32, packed_count);
        if (packed_count == 1) {
            packed_ins[0] = unboundIn(binds, ins) orelse return error.Invalid;
        } else for (packed_ins) |*v| {
            const i = try p.number();
            if (i >= ins) return error.Invalid;
            for (binds) |b| if (b.in == i) return error.Invalid;
            v.* = @intCast(i);
        }
        return .{ .coders = coders, .binds = binds, .packed_ins = packed_ins };
    }

    fn unboundIn(binds: []const Bind, ins: u32) ?u32 {
        var i: u32 = 0;
        while (i < ins) : (i += 1) {
            if (!boundIn(binds, i)) return i;
        }
        return null;
    }

    fn boundIn(binds: []const Bind, in: u32) bool {
        for (binds) |b| if (b.in == in) return true;
        return false;
    }

    /// The defaults when a header has no SubStreamsInfo: one substream a
    /// folder, its size and CRC the folder's.
    fn defaultSubstreams(p: *Parser, s: *Streams) Error!void {
        const sizes = try p.arena.alloc(u64, s.folders.len);
        const crcs = try p.arena.alloc(?u32, s.folders.len);
        for (s.folders, sizes, crcs, 0..) |*f, *size, *crc, i| {
            f.streams = 1;
            f.first_stream = @intCast(i);
            size.* = f.size();
            crc.* = f.crc;
        }
        s.stream_sizes = sizes;
        s.stream_crcs = crcs;
    }

    fn substreams(p: *Parser, s: *Streams) Error!void {
        var t = try p.number();
        var total: u64 = s.folders.len;
        if (t == id.num_unpack_stream) {
            total = 0;
            for (s.folders) |*f| {
                // Each substream past a folder's first takes a size.
                const n = try p.number();
                if (n > 1 and n - 1 > p.bytes.len - p.at) return error.Invalid;
                f.streams = @intCast(n);
                total += n;
                if (total > p.bytes.len + s.folders.len) return error.Invalid;
            }
            t = try p.number();
        }
        const sizes = try p.arena.alloc(u64, @intCast(total));
        var at: u32 = 0;
        for (s.folders) |*f| {
            f.first_stream = at;
            if (f.streams == 0) continue;
            const whole = f.size();
            var sum: u64 = 0;
            if (t == id.size) {
                for (sizes[at..][0 .. f.streams - 1]) |*v| {
                    v.* = try p.number();
                    sum = std.math.add(u64, sum, v.*) catch return error.Invalid;
                }
            } else if (f.streams > 1) return error.Invalid;
            if (sum > whole) return error.Invalid;
            sizes[at + f.streams - 1] = whole - sum;
            at += f.streams;
        }
        if (t == id.size) t = try p.number();
        const crcs = try p.arena.alloc(?u32, @intCast(total));
        @memset(crcs, null);
        // A folder of one substream whose CRC it gives has it already.
        var unknown: usize = 0;
        for (s.folders) |*f| {
            if (f.streams == 1 and f.crc != null) {
                crcs[f.first_stream] = f.crc;
            } else unknown += f.streams;
        }
        while (t != id.end) : (t = try p.number()) {
            if (t != id.crc) {
                try p.skipData();
                continue;
            }
            const given = try p.digests(unknown);
            var k: usize = 0;
            for (s.folders) |*f| {
                if (f.streams == 1 and f.crc != null) continue;
                for (crcs[f.first_stream..][0..f.streams]) |*c| {
                    c.* = given[k];
                    k += 1;
                }
            }
        }
        s.stream_sizes = sizes;
        s.stream_crcs = crcs;
    }

    /// Each folder's coders form what the format allows: one unbound
    /// out-stream, and the packed streams in range.
    fn checkFolders(s: *Streams) Error!void {
        for (s.folders) |*f| {
            var outs: u32 = 0;
            for (f.coders) |c| outs += c.outs;
            var unbound: u32 = 0;
            var o: u32 = 0;
            while (o < outs) : (o += 1) {
                for (f.binds) |b| {
                    if (b.out == o) break;
                } else unbound += 1;
            }
            if (unbound != 1) return error.Invalid;
        }
    }

    // -----------------------------------------------------------------
    // The header

    /// The header after its `header` ID.
    pub fn header(p: *Parser) Error!Header {
        var h: Header = .{};
        var t = try p.number();
        if (t == id.archive_properties) {
            while (try p.number() != id.end) try p.skipData();
            t = try p.number();
        }
        if (t == id.additional_streams) return error.Unsupported;
        if (t == id.main_streams) {
            h.streams = try p.streams();
            t = try p.number();
        }
        if (t == id.files_info) {
            h.files = try p.files(&h.streams);
            t = try p.number();
        }
        if (t != id.end) return error.Invalid;
        return h;
    }

    fn files(p: *Parser, s: *const Streams) Error![]File {
        const n = try p.number();
        if (Limits.overEntries(p.limits.entries, n)) return error.LimitExceeded;
        // An entry takes at least a bit of the header, in its empty-stream
        // vector or as a substream.
        if (n > (p.bytes.len - p.at) * 8 + s.stream_sizes.len) return error.Invalid;
        const out = try p.arena.alloc(File, @intCast(n));
        @memset(out, .{});
        var empty: usize = 0;
        var empty_files: ?[]bool = null;
        var anti: ?[]bool = null;
        while (true) {
            const t = try p.number();
            if (t == id.end) break;
            const len = try p.number();
            var sub: Parser = .{ .arena = p.arena, .bytes = try p.take(len), .limits = p.limits };
            const base = p.at - sub.bytes.len;
            errdefer p.at = base + sub.at;
            switch (t) {
                id.empty_stream => {
                    const v = try sub.bools(out.len);
                    empty = 0;
                    for (out, v) |*f, e| {
                        f.stream = !e;
                        if (e) empty += 1;
                    }
                },
                id.empty_file => empty_files = try sub.bools(empty),
                id.anti => anti = try sub.bools(empty),
                id.name => try sub.names(out),
                id.mtime, id.atime, id.ctime => try sub.times(out, t),
                id.attributes => {
                    const which = try sub.defined(out.len);
                    if (try sub.byte() != 0) return error.Unsupported;
                    for (out, which) |*f, has| {
                        if (has) f.attributes = try sub.int(u32);
                    }
                },
                else => {},
            }
        }
        var k: usize = 0;
        for (out) |*f| {
            if (f.stream) continue;
            if (empty_files) |v| if (k < v.len) {
                f.empty_file = v[k];
            };
            if (anti) |v| if (k < v.len) {
                f.anti = v[k];
            };
            k += 1;
        }
        var with_stream: u64 = 0;
        for (out) |f| {
            if (f.stream) with_stream += 1;
        }
        if (with_stream != s.stream_sizes.len) return error.Invalid;
        return out;
    }

    fn names(p: *Parser, out: []File) Error!void {
        if (try p.byte() != 0) return error.Unsupported;
        for (out) |*f| {
            const start = p.at;
            while (true) {
                const unit = try p.take(2);
                if (unit[0] == 0 and unit[1] == 0) break;
            }
            f.name = p.bytes[start .. p.at - 2];
        }
    }

    fn times(p: *Parser, out: []File, which_time: u64) Error!void {
        const which = try p.defined(out.len);
        if (try p.byte() != 0) return error.Unsupported;
        for (out, which) |*f, has| {
            if (!has) continue;
            const t = try p.int(u64);
            switch (which_time) {
                id.mtime => f.mtime = t,
                id.atime => f.atime = t,
                else => f.ctime = t,
            }
        }
    }
};

test "numbers: the first byte's leading ones count the bytes after it" {
    var p: Parser = .{ .arena = std.testing.allocator, .bytes = &.{ 0x7f, 0x80, 0x80, 0xc1, 0x02, 0x03, 0xff, 1, 2, 3, 4, 5, 6, 7, 8 }, .limits = .{} };
    try std.testing.expectEqual(@as(u64, 0x7f), try p.number());
    try std.testing.expectEqual(@as(u64, 0x80), try p.number());
    try std.testing.expectEqual(@as(u64, 0x010302), try p.number());
    try std.testing.expectEqual(@as(u64, 0x0807060504030201), try p.number());
    try std.testing.expectError(error.Invalid, p.number());
}
