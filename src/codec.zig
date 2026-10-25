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
    lzma = 14,
    zstd = 93,
    xz = 95,
    /// WinZip AES: the real method is in the entry's 0x9901 field.
    aes = 99,
    _,
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
    buffer: []u8 = &.{},

    const State = union(enum) {
        stored: *Io.Reader,
        deflate: warp.Inflate.Reader,
        zstd: warp.zstd.Decompress.Reader,
    };

    pub const Options = struct {
        limits: Limits = .{},
        /// The stream ends at its codec's own end and what follows is not
        /// its (an entry with a data descriptor): one zstd frame, not all
        /// the frames until the input ends.
        self_terminated: bool = false,
    };

    pub fn init(d: *Decoder, gpa: Allocator, method: Method, input: *Io.Reader, options: Options) DecodeError!void {
        const limits = options.limits;
        d.* = .{ .gpa = gpa, .state = .{ .stored = input } };
        switch (method) {
            .stored => {},
            .deflate => {
                const inflate: warp.Inflate.Options = .{ .accept = .raw, .window_bits = 15 };
                d.buffer = try gpa.alloc(u8, (1 << 15) + 4096);
                d.state = .{ .deflate = .init(input, d.buffer, inflate) };
            },
            .deflate64 => {
                // Zip method 9 and 7z's Deflate64 coder: DEFLATE's engine with
                // the extended alphabet and a 64 KiB window.
                const inflate: warp.Inflate.Options = .{ .accept = .raw, .format = .deflate64 };
                if (Limits.over(limits.window, inflate.windowLen())) return error.LimitExceeded;
                d.buffer = try gpa.alloc(u8, inflate.windowLen() + 4096);
                d.state = .{ .deflate = .init(input, d.buffer, inflate) };
            },
            .zstd => {
                // The frame's own header names its window: the buffer is
                // sized by it, after it is checked against the limit.
                const head = input.peek(18) catch |e| switch (e) {
                    // A stream shorter than the longest frame header.
                    error.EndOfStream => input.peekGreedy(1) catch |short| switch (short) {
                        error.EndOfStream => return error.Invalid,
                        error.ReadFailed => return error.ReadFailed,
                    },
                    error.ReadFailed => return error.ReadFailed,
                };
                // An entry's stream starts with its frame: a skippable
                // frame first names no window to size the buffer by.
                const fh = switch (warp.zstd.frameHeader(head, .standard) catch return error.Invalid) {
                    .zstd => |h| h,
                    .skippable => return error.Invalid,
                };
                const window = fh.window_size;
                if (Limits.over(limits.window, window)) return error.LimitExceeded;
                const block = @min(window, 128 * 1024);
                d.buffer = try gpa.alloc(u8, 4096 + @as(usize, @intCast(window)) + block + warp.zstd.decompress_margin);
                d.state = .{ .zstd = .init(input, d.buffer, .{ .frames = if (options.self_terminated) .one else .all }) };
            },
            else => return error.UnsupportedMethod,
        }
    }

    pub fn deinit(d: *Decoder) void {
        d.gpa.free(d.buffer);
        d.* = undefined;
    }

    /// The decoded bytes.
    pub fn reader(d: *Decoder) *Io.Reader {
        return switch (d.state) {
            .stored => |r| r,
            .deflate => |*r| &r.interface,
            .zstd => |*r| &r.interface,
        };
    }

    /// Whether the decoder's `error.ReadFailed` was the stream's own (a
    /// corrupt stream) and not its input's.
    pub fn failed(d: *const Decoder) bool {
        return switch (d.state) {
            .stored => false,
            .deflate => |*r| r.err() != null,
            .zstd => |*r| r.err() != null,
        };
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
    try std.testing.expectError(error.UnsupportedMethod, d.init(std.testing.allocator, .lzma, &in, .{}));
}
