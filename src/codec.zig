//! The compression methods archives name, each through warp: a decoder
//! that reads an entry's compressed bytes as its contents, and an encoder
//! that writes contents compressed. A method warp lacks is refused by name.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const warp = @import("warp");
const Limits = @import("Limits.zig");

/// A compression method by zip's numbering (APPNOTE 4.4.5), which 7z's
/// coders map onto.
pub const Method = enum(u16) {
    stored = 0,
    deflate = 8,
    deflate64 = 9,
    bzip2 = 12,
    /// LZMA, its properties leading the stream (APPNOTE 5.8.8).
    lzma = 14,
    zstd = 93,
    xz = 95,
    ppmd = 98,
    /// WinZip AES: the real method is in the entry's 0x9901 field.
    aes = 99,
    _,
};

/// What a decoder decodes: a zip method, whose stream carries what it
/// needs, or one of 7z's coders whose properties are kept apart from the
/// stream.
pub const Coder = union(enum) {
    method: Method,
    /// Raw LZMA.
    lzma: struct { properties: warp.lzma.Properties, dictionary: u32 },
    /// Raw LZMA2.
    lzma2: struct { dictionary: u32 },
    /// Delta or a branch converter, as xz has them.
    filter: warp.xz.Filter,
};

pub const DecodeError = error{
    /// warp has no decoder for the method yet.
    UnsupportedMethod,
    /// The stream's own header asks for more history than `Limits.window`.
    LimitExceeded,
    /// The stream's header is malformed.
    Invalid,
    ReadFailed,
    OutOfMemory,
};

/// A method's decoder over the compressed bytes `input` gives. It is
/// initialized in place and must not move while its reader is used.
pub const Decoder = struct {
    gpa: Allocator,
    state: State,
    /// The window and buffer the decoder reads into.
    buffer: []align(4) u8 = &.{},

    const State = union(enum) {
        stored: *Io.Reader,
        deflate: warp.Inflate.Reader,
        zstd: Zstd,
        lzma: warp.lzma.Decompress.Reader,
        xz: warp.xz.Decompress.Reader,
        bzip2: warp.bzip2.Decompress.Reader,
        filter: warp.xz.FilterReader,
    };

    /// The reader's own buffering, before a codec's window.
    const read_len = 4096;

    pub const Options = struct {
        limits: Limits = .{},
        /// The stream ends at its codec's own end and what follows is not
        /// its (an entry with a data descriptor): one zstd frame, or one
        /// bzip2 or xz stream, not all of them until the input ends.
        self_terminated: bool = false,
        /// The decoded length where the archive declares it: an LZMA
        /// stream ends there, with or without its end marker, and keeps no
        /// more history than it.
        size: ?u64 = null,
    };

    pub fn init(d: *Decoder, gpa: Allocator, coder: Coder, input: *Io.Reader, options: Options) DecodeError!void {
        const limits = options.limits;
        d.* = .{ .gpa = gpa, .state = .{ .stored = input } };
        const method = switch (coder) {
            .method => |m| m,
            .lzma => |l| return d.initLzma(input, l.properties, l.dictionary, options),
            .lzma2 => |l| return d.initLzma(input, null, l.dictionary, options),
            .filter => |f| {
                d.buffer = try gpa.alignedAlloc(u8, .@"4", read_len);
                d.state = .{ .filter = .init(input, d.buffer, f) };
                return;
            },
        };
        switch (method) {
            .stored => {},
            .deflate => {
                const inflate: warp.Inflate.Options = .{ .accept = .raw, .window_bits = 15 };
                d.buffer = try gpa.alignedAlloc(u8, .@"4", (1 << 15) + read_len);
                d.state = .{ .deflate = .init(input, d.buffer, inflate) };
            },
            .deflate64 => {
                // Zip method 9 and 7z's Deflate64 coder: DEFLATE's engine with
                // the extended alphabet and a 64 KiB window.
                const inflate: warp.Inflate.Options = .{ .accept = .raw, .format = .deflate64 };
                if (Limits.over(limits.window, inflate.windowLen())) return error.LimitExceeded;
                d.buffer = try gpa.alignedAlloc(u8, .@"4", inflate.windowLen() + read_len);
                d.state = .{ .deflate = .init(input, d.buffer, inflate) };
            },
            .bzip2 => {
                // The block's vector, the most a level-9 stream needs: bzip2
                // keeps no history beyond its block.
                d.buffer = try gpa.alignedAlloc(u8, .@"4", read_len + warp.bzip2.Decompress.memory);
                d.state = .{ .bzip2 = .init(input, d.buffer, .{ .streams = if (options.self_terminated) .one else .all }) };
            },
            .lzma => {
                // Zip's LZMA: LZMA SDK's version (two bytes), the
                // properties' length, then the five bytes of raw LZMA's
                // properties.
                const head = input.takeArray(9) catch |e| return switch (e) {
                    error.EndOfStream => error.Invalid,
                    error.ReadFailed => error.ReadFailed,
                };
                if (std.mem.readInt(u16, head[2..4], .little) != 5) return error.Invalid;
                const properties = warp.lzma.Properties.parse(head[4]) orelse return error.Invalid;
                const dictionary = std.mem.readInt(u32, head[5..9], .little);
                return d.initLzma(input, properties, dictionary, options);
            },
            .xz => {
                // Zip method 95: an .xz stream, whose dictionary each block's
                // header names. The reader allocates the window as the
                // blocks ask, within `Limits.window`.
                const max_window = std.math.cast(usize, limits.window.raw()) orelse std.math.maxInt(usize);
                d.buffer = try gpa.alignedAlloc(u8, .@"4", read_len);
                d.state = .{ .xz = .init(gpa, input, d.buffer, max_window, .{ .streams = if (options.self_terminated) .one else .all }) };
            },
            .zstd => {
                d.state = .{ .zstd = .{ .input = input, .gpa = gpa, .limit = limits.window, .all = !options.self_terminated } };
                d.state.zstd.interface.buffer = &d.state.zstd.own;
                // An entry's stream starts with a frame.
                const first = try Zstd.nextFrame(input) orelse return error.Invalid;
                try d.state.zstd.begin(first);
            },
            else => return error.UnsupportedMethod,
        }
    }

    /// LZMA with `properties`, or LZMA2 without, over a window for
    /// `dictionary`, or for the declared size where that is less: no
    /// distance reaches before the start.
    fn initLzma(d: *Decoder, input: *Io.Reader, properties: ?warp.lzma.Properties, dictionary: u32, options: Options) DecodeError!void {
        const held = @min(dictionary, options.size orelse dictionary);
        const window = warp.lzma.Decompress.windowLength(held);
        if (Limits.over(options.limits.window, window)) return error.LimitExceeded;
        d.buffer = try d.gpa.alignedAlloc(u8, .@"4", read_len + window);
        const format: warp.lzma.Decompress.Format = if (properties) |p| .{ .lzma1 = .{ .properties = p, .dictionary = held, .size = options.size } } else .{ .lzma2 = .{ .dictionary = held } };
        d.state = .{ .lzma = .init(input, d.buffer[0..read_len], d.buffer[read_len..], format, .{}) };
    }

    pub fn deinit(d: *Decoder) void {
        switch (d.state) {
            .zstd => |z| d.gpa.free(z.memory),
            .xz => |*r| r.deinit(),
            else => {},
        }
        d.gpa.free(d.buffer);
        d.* = undefined;
    }

    /// The decoded bytes.
    pub fn reader(d: *Decoder) *Io.Reader {
        return switch (d.state) {
            .stored => |r| r,
            .deflate => |*r| &r.interface,
            .zstd => |*r| &r.interface,
            .lzma => |*r| &r.interface,
            .xz => |*r| &r.interface,
            .bzip2 => |*r| &r.interface,
            .filter => |*r| &r.interface,
        };
    }

    /// What failed behind the decoder's `error.ReadFailed`.
    pub const Failure = error{
        /// The stream is corrupt.
        CorruptStream,
        /// A header met mid-stream (a later zstd frame's, an xz block's)
        /// asks more history than `Limits.window`.
        LimitExceeded,
        /// The memory for a window a later header asks.
        OutOfMemory,
    };

    /// The decoder's own failure behind an `error.ReadFailed`; null when
    /// it was its input's.
    pub fn failure(d: *const Decoder) ?Failure {
        return switch (d.state) {
            // A converter takes any bytes.
            .stored, .filter => null,
            .deflate => |*r| if (r.err() != null) error.CorruptStream else null,
            .zstd => |*r| if (r.failure) |e| switch (e) {
                error.LimitExceeded => error.LimitExceeded,
                error.OutOfMemory => error.OutOfMemory,
                error.UnsupportedMethod, error.Invalid, error.ReadFailed => error.CorruptStream,
            } else if (r.frame.err() != null) error.CorruptStream else null,
            .lzma => |*r| if (r.err() != null) error.CorruptStream else null,
            .xz => |*r| if (r.err()) |e| switch (e) {
                error.WindowTooLarge => error.LimitExceeded,
                error.OutOfMemory => error.OutOfMemory,
                else => error.CorruptStream,
            } else null,
            .bzip2 => |*r| if (r.err() != null) error.CorruptStream else null,
        };
    }
};

/// zstd's frames one at a time, each over the window its own header
/// names: a stream's frames may name different windows (7-Zip's starts
/// with an empty frame of a small one), so the memory grows to the
/// largest, within `Limits.window`, as the frames come.
const Zstd = struct {
    interface: Io.Reader = .{ .vtable = &.{ .stream = stream, .readVec = readVec }, .buffer = &.{}, .seek = 0, .end = 0 },
    own: [Decoder.read_len]u8 = undefined,
    input: *Io.Reader,
    gpa: Allocator,
    limit: Limits.Bytes,
    /// Every frame until the input ends, or the first alone.
    all: bool,
    frame: warp.zstd.Decompress.Reader = undefined,
    memory: []align(4) u8 = &.{},
    /// A later frame's header was malformed or past the limit.
    failure: ?DecodeError = null,

    /// The next zstd frame's header, skippable frames before it read
    /// through; null where the input ends.
    fn nextFrame(input: *Io.Reader) DecodeError!?warp.zstd.FrameHeader {
        while (true) {
            const head = input.peek(18) catch |e| switch (e) {
                // A stream shorter than the longest frame header.
                error.EndOfStream => input.peekGreedy(1) catch |short| switch (short) {
                    error.EndOfStream => return null,
                    error.ReadFailed => return error.ReadFailed,
                },
                error.ReadFailed => return error.ReadFailed,
            };
            switch (warp.zstd.frameHeader(head, .standard) catch return error.Invalid) {
                .zstd => |h| return h,
                .skippable => |s| input.discardAll(8 + @as(usize, s.len)) catch |e| return switch (e) {
                    error.EndOfStream => error.Invalid,
                    error.ReadFailed => error.ReadFailed,
                },
            }
        }
    }

    /// Decodes the frame `h` heads, in memory sized by its window.
    fn begin(z: *Zstd, h: warp.zstd.FrameHeader) DecodeError!void {
        if (Limits.over(z.limit, h.window_size)) return error.LimitExceeded;
        const need = Decoder.read_len + @as(usize, @intCast(h.window_size)) + h.blockMax() + warp.zstd.decompress_margin;
        if (need > z.memory.len) {
            z.gpa.free(z.memory);
            z.memory = &.{};
            z.memory = try z.gpa.alignedAlloc(u8, .@"4", need);
        }
        z.frame = .init(z.input, z.memory, .{ .frames = .one });
    }

    fn readInto(z: *Zstd, out: []u8) Io.Reader.Error!usize {
        while (true) {
            const n = try z.frame.interface.readSliceShort(out);
            if (n != 0 or out.len == 0) return n;
            if (!z.all) return error.EndOfStream;
            const next = nextFrame(z.input) catch |e| {
                if (e != error.ReadFailed) z.failure = e;
                return error.ReadFailed;
            };
            const h = next orelse return error.EndOfStream;
            z.begin(h) catch |e| {
                z.failure = e;
                return error.ReadFailed;
            };
        }
    }

    fn stream(interface: *Io.Reader, writer: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const z: *Zstd = @alignCast(@fieldParentPtr("interface", interface));
        _ = writer;
        if (limit == .nothing) return 0;
        const n = try z.readInto(limit.slice(interface.buffer));
        interface.seek = 0;
        interface.end = n;
        return 0;
    }

    fn readVec(interface: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const z: *Zstd = @alignCast(@fieldParentPtr("interface", interface));
        if (data[0].len != 0) return z.readInto(data[0]);
        const n = try z.readInto(interface.buffer[interface.end..]);
        interface.end += n;
        return 0;
    }
};

pub const EncodeError = error{
    /// warp has no encoder for the method.
    UnsupportedMethod,
    OutOfMemory,
};

/// A method's encoder writing compressed bytes to `output`. It is
/// initialized in place and must not move while its writer is used.
pub const Encoder = struct {
    gpa: Allocator,
    state: State,
    staging: []u8 = &.{},

    const State = union(enum) {
        stored: *Io.Writer,
        deflate: struct { engine: warp.Deflate, writer: warp.Deflate.Writer },
        zstd: struct { engine: warp.zstd.Compress, writer: warp.zstd.Compress.Writer },
    };

    pub const Options = struct {
        /// warp's level for the method: DEFLATE 0-12, zstd 1-22; null is
        /// the method's default.
        level: ?i32 = null,
        /// The contents' length when known, which zstd writes in its frame.
        size: ?u64 = null,
    };

    pub fn init(e: *Encoder, gpa: Allocator, method: Method, output: *Io.Writer, options: Options) EncodeError!void {
        e.* = .{ .gpa = gpa, .state = .{ .stored = output } };
        switch (method) {
            .stored => {},
            .deflate => {
                const level: u4 = @intCast(std.math.clamp(options.level orelse 6, 0, 12));
                e.staging = try gpa.alloc(u8, 16 * 1024);
                errdefer gpa.free(e.staging);
                e.state = .{ .deflate = .{ .engine = try .init(gpa, .{ .level = level, .container = .raw }), .writer = undefined } };
                e.state.deflate.writer = .init(&e.state.deflate.engine, output, e.staging);
            },
            .zstd => {
                const level = std.math.clamp(options.level orelse warp.zstd.default_level, warp.zstd.min_level, warp.zstd.max_level);
                e.staging = try gpa.alloc(u8, 16 * 1024);
                errdefer gpa.free(e.staging);
                const pledged: ?@import("aegis").units.Bytes(u64) = if (options.size) |n| .fromRaw(n) else null;
                e.state = .{ .zstd = .{ .engine = try .init(gpa, .{ .level = level, .pledged_size = pledged }), .writer = undefined } };
                e.state.zstd.writer = .init(&e.state.zstd.engine, output, e.staging);
            },
            else => return error.UnsupportedMethod,
        }
    }

    pub fn deinit(e: *Encoder) void {
        switch (e.state) {
            .stored => {},
            .deflate => |*s| s.engine.deinit(),
            .zstd => |*s| s.engine.deinit(),
        }
        e.gpa.free(e.staging);
        e.* = undefined;
    }

    /// Where the contents are written.
    pub fn writer(e: *Encoder) *Io.Writer {
        return switch (e.state) {
            .stored => |w| w,
            .deflate => |*s| &s.writer.interface,
            .zstd => |*s| &s.writer.interface,
        };
    }

    /// Ends the compressed stream; the output is not flushed.
    pub fn finish(e: *Encoder) Io.Writer.Error!void {
        switch (e.state) {
            .stored => {},
            .deflate => |*s| try s.writer.finish(),
            .zstd => |*s| try s.writer.finish(),
        }
    }
};

test "a method warp lacks is refused by name" {
    var d: Decoder = undefined;
    var in: Io.Reader = .fixed("");
    try std.testing.expectError(error.UnsupportedMethod, d.init(std.testing.allocator, .{ .method = .ppmd }, &in, .{}));
}

test "zip's LZMA header is read, and one that breaks it refused" {
    const gpa = std.testing.allocator;
    var d: Decoder = undefined;
    // Properties of four bytes, not five.
    var bad: Io.Reader = .fixed("\x10\x02\x04\x00\x5d\x00\x00\x01\x00");
    try std.testing.expectError(error.Invalid, d.init(gpa, .{ .method = .lzma }, &bad, .{}));
    // A properties byte past 224.
    var props: Io.Reader = .fixed("\x10\x02\x05\x00\xe1\x00\x00\x01\x00");
    try std.testing.expectError(error.Invalid, d.init(gpa, .{ .method = .lzma }, &props, .{}));
    var short: Io.Reader = .fixed("\x10\x02\x05\x00\x5d");
    try std.testing.expectError(error.Invalid, d.init(gpa, .{ .method = .lzma }, &short, .{}));
    // A 1 GiB dictionary over a 128 MiB limit.
    var big: Io.Reader = .fixed("\x10\x02\x05\x00\x5d\x00\x00\x00\x40");
    try std.testing.expectError(error.LimitExceeded, d.init(gpa, .{ .method = .lzma }, &big, .{}));
}

test "zip's xz is read over the window its block's header asks, and one past the limit refused there" {
    const gpa = std.testing.allocator;
    // "abc" by liblzma at preset 0 (a 256 KiB dictionary), without a check:
    // the block's header names no sizes.
    const stream = "\xfd\x37\x7a\x58\x5a\x00\x00\x00\xff\x12\xd9\x41\x02\x00\x21\x01\x0c\x00\x00\x00\x8f\x98\x41\x9c\x01\x00\x02\x61\x62\x63\x00\x00\x00\x01\x13\x03\x03\xa5\x60\xd8\x06\x72\x9e\x7a\x01\x00\x00\x00\x00\x00\x59\x5a";
    {
        var in: Io.Reader = .fixed(stream);
        var d: Decoder = undefined;
        try d.init(gpa, .{ .method = .xz }, &in, .{});
        defer d.deinit();
        const got = try d.reader().allocRemaining(gpa, .unlimited);
        defer gpa.free(got);
        try std.testing.expectEqualStrings("abc", got);
    }
    {
        var in: Io.Reader = .fixed(stream);
        var d: Decoder = undefined;
        try d.init(gpa, .{ .method = .xz }, &in, .{ .limits = .{ .window = .literal("64KiB") } });
        defer d.deinit();
        try std.testing.expectError(error.ReadFailed, d.reader().allocRemaining(gpa, .unlimited));
        try std.testing.expectEqual(error.LimitExceeded, d.failure().?);
    }
}

test "an LZMA window is no larger than the declared contents" {
    const gpa = std.testing.allocator;
    var d: Decoder = undefined;
    var in: Io.Reader = .fixed("");
    // 1 GiB declared, 100 bytes of contents: the window is LZMA's least.
    try d.init(gpa, .{ .lzma2 = .{ .dictionary = 1 << 30 } }, &in, .{ .size = 100 });
    defer d.deinit();
    try std.testing.expectEqual(Decoder.read_len + warp.lzma.Decompress.windowLength(100), d.buffer.len);
}
