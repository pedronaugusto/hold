//! 7z's AES coder (06F10701), read: AES-256 in CBC mode, its key SHA-256
//! run 2^cycles times over the salt, the password as UTF-16LE and a
//! 64-bit counter (7-Zip's `7zAes.cpp`). The coder carries no MAC: a
//! wrong password shows only as the stream after it failing or its CRC.
const std = @import("std");
const Io = std.Io;
const aegis = @import("aegis");
const crypto = std.crypto;
const Aes256 = crypto.core.aes.Aes256;
const Sha256 = crypto.hash.sha2.Sha256;

/// 7-Zip's own bound on the key's rounds (2^24); a header asking more is
/// refused, so no archive can spend a caller's time on the key alone.
pub const max_cycles = 24;
/// The cycles value that means no hashing: the salt and password are the
/// key.
const raw_cycles = 0x3f;
/// The longest password, in bytes of UTF-8.
pub const max_password = 1024;

pub const Props = struct {
    cycles: u6,
    salt: [16]u8 = @splat(0),
    salt_len: u8 = 0,
    iv: [16]u8 = @splat(0),
};

pub const PropsError = error{
    /// Properties that break the coder's layout.
    Invalid,
    /// More rounds than `max_cycles`.
    UnsupportedEncryption,
};

/// The coder's properties: the rounds' exponent, then the salt's and IV's
/// lengths and bytes.
pub fn parseProps(props: []const u8) PropsError!Props {
    if (props.len == 0) return error.Invalid;
    const b0 = props[0];
    var p: Props = .{ .cycles = @intCast(b0 & 0x3f) };
    if (p.cycles > max_cycles and p.cycles != raw_cycles) return error.UnsupportedEncryption;
    if (b0 & 0xc0 == 0) return p;
    if (props.len < 2) return error.Invalid;
    const b1 = props[1];
    const salt_len: usize = ((b0 >> 7) & 1) + (b1 >> 4);
    const iv_len: usize = ((b0 >> 6) & 1) + (b1 & 0x0f);
    if (props.len != 2 + salt_len + iv_len) return error.Invalid;
    @memcpy(p.salt[0..salt_len], props[2..][0..salt_len]);
    p.salt_len = @intCast(salt_len);
    @memcpy(p.iv[0..iv_len], props[2 + salt_len ..][0..iv_len]);
    return p;
}

pub const KeyError = error{
    /// A password that is not UTF-8, or longer than `max_password` bytes.
    UnsupportedEncryption,
};

/// The key, into `key`: SHA-256 over 2^cycles rounds of salt, password
/// and counter.
pub fn deriveKey(props: Props, password: *const aegis.SecretBytes, key: *aegis.Secret([32]u8)) KeyError!void {
    // UTF-8 never takes fewer bytes than UTF-16 units, so these fit.
    if (password.expose().len > max_password) return error.UnsupportedEncryption;
    var units = aegis.Secret([max_password]u16).init(undefined);
    defer units.deinit();
    const n = std.unicode.utf8ToUtf16Le(units.exposeMut(), password.expose()) catch return error.UnsupportedEncryption;
    const pw = std.mem.sliceAsBytes(units.expose()[0..n]);
    const k = key.exposeMut();
    @memset(k, 0);
    const salt = props.salt[0..props.salt_len];
    if (props.cycles == raw_cycles) {
        const a = @min(salt.len, 32);
        @memcpy(k[0..a], salt[0..a]);
        const b = @min(pw.len, 32 - a);
        @memcpy(k[a..][0..b], pw[0..b]);
        return;
    }
    var h = Sha256.init(.{});
    var round: u64 = 0;
    const rounds = @as(u64, 1) << props.cycles;
    while (round < rounds) : (round += 1) {
        h.update(salt);
        h.update(pw);
        var counter: [8]u8 = undefined;
        std.mem.writeInt(u64, &counter, round, .little);
        h.update(&counter);
    }
    h.final(k);
    crypto.secureZero(u8, std.mem.asBytes(&h));
}

pub const Error = error{
    /// The stream ended inside its ciphertext.
    Truncated,
};

/// The plaintext of `total` bytes of ciphertext, cut to `size`: CBC pads
/// the stream to whole blocks. Initialized in place; must not move while
/// its reader is used.
pub const Reader = struct {
    interface: Io.Reader,
    /// Private: the ciphertext.
    inner: *Io.Reader,
    /// Private: plaintext bytes still to give.
    left: u64,
    ctx: crypto.core.aes.AesDecryptCtx(Aes256),
    /// Private: the last ciphertext block, the next block's chain.
    chain: [16]u8,
    /// Private: the block decrypted and how much of it was given.
    block: [16]u8 = undefined,
    used: u8 = 16,
    failure: ?Error = null,
    /// Private: staged plaintext, for a decoder that reads it in place.
    staging: [16 * 1024]u8 = undefined,

    pub const InitError = error{
        /// Ciphertext that is not whole blocks, or shorter than `size`.
        Invalid,
    };

    pub fn init(r: *Reader, inner: *Io.Reader, total: u64, size: u64, props: Props, key: *const aegis.Secret([32]u8)) InitError!void {
        if (total % 16 != 0 or size > total) return error.Invalid;
        r.* = .{
            .interface = .{ .vtable = &vtable, .buffer = &.{}, .seek = 0, .end = 0 },
            .inner = inner,
            .left = size,
            .ctx = .init(key.expose().*),
            .chain = props.iv,
        };
        r.interface.buffer = &r.staging;
    }

    /// Erases the key schedule and the plaintext held.
    pub fn deinit(r: *Reader) void {
        crypto.secureZero(u8, std.mem.asBytes(&r.ctx));
        crypto.secureZero(u8, &r.block);
        crypto.secureZero(u8, &r.staging);
    }

    pub fn err(r: *const Reader) ?Error {
        return r.failure;
    }

    const vtable: Io.Reader.VTable = .{ .stream = stream };

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r)); // safe: the vtable is installed only on a Reader's interface
        if (r.left == 0) return error.EndOfStream;
        const out = limit.min(.limited64(r.left)).slice(try w.writableSliceGreedy(1));
        var n: usize = 0;
        while (n < out.len) {
            if (r.used == 16) try r.next();
            const k = @min(16 - r.used, out.len - n);
            @memcpy(out[n..][0..k], r.block[r.used..][0..k]);
            r.used += @intCast(k);
            n += k;
        }
        r.left -= n;
        w.advance(n);
        return n;
    }

    fn next(r: *Reader) Io.Reader.StreamError!void {
        var cipher: [16]u8 = undefined;
        r.inner.readSliceAll(&cipher) catch |e| return switch (e) {
            error.EndOfStream => r.fail(error.Truncated),
            error.ReadFailed => error.ReadFailed,
        };
        r.ctx.decrypt(&r.block, &cipher);
        for (&r.block, r.chain) |*b, c| b.* ^= c;
        r.chain = cipher;
        r.used = 0;
    }

    fn fail(r: *Reader, e: Error) error{ReadFailed} {
        r.failure = e;
        return error.ReadFailed;
    }
};

test "props: the rounds, then salt and IV" {
    const p = try parseProps(&.{ 0x13 | 0xc0, 0x00, 0xaa, 0xbb });
    try std.testing.expectEqual(@as(u6, 19), p.cycles);
    try std.testing.expectEqualSlices(u8, &.{0xaa}, p.salt[0..p.salt_len]);
    try std.testing.expectEqual(@as(u8, 0xbb), p.iv[0]);
    try std.testing.expectError(error.UnsupportedEncryption, parseProps(&.{30}));
    try std.testing.expectError(error.Invalid, parseProps(&.{ 0xc0, 0x00, 0xaa }));
}

test "a block decrypts in CBC order and is cut to its size" {
    var key = aegis.Secret([32]u8).init(@splat(7));
    defer key.deinit();
    const iv: [16]u8 = @splat(3);
    const enc = crypto.core.aes.Aes256.initEnc(key.expose().*);
    var plain: [32]u8 = undefined;
    for (&plain, 0..) |*b, i| b.* = @intCast(i);
    var cipher: [32]u8 = undefined;
    var chain = iv;
    for (0..2) |i| {
        var x: [16]u8 = plain[i * 16 ..][0..16].*;
        for (&x, chain) |*b, c| b.* ^= c;
        enc.encrypt(cipher[i * 16 ..][0..16], &x);
        chain = cipher[i * 16 ..][0..16].*;
    }
    var in: Io.Reader = .fixed(&cipher);
    var r: Reader = undefined;
    try r.init(&in, 32, 20, .{ .cycles = 0, .iv = iv }, &key);
    defer r.deinit();
    var got: [32]u8 = undefined;
    var w: Io.Writer = .fixed(&got);
    try std.testing.expectEqual(@as(usize, 20), try r.interface.streamRemaining(&w));
    try std.testing.expectEqualSlices(u8, plain[0..20], w.buffered());
}
