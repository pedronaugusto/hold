//! WinZip AES (AE-1 and AE-2), read: a salt and a password verifier before
//! the encrypted contents, AES in counter mode with a little-endian
//! counter from one, and ten bytes of HMAC-SHA1 over the ciphertext after
//! them. Keys come from PBKDF2-HMAC-SHA1 over the password and salt, 1,000
//! rounds, as the format fixes. 128- and 256-bit keys are read; Zig's std
//! has no AES-192, so strength 2 is refused by name.
const std = @import("std");
const Io = std.Io;
const aegis = @import("aegis");
const crypto = std.crypto;
const HmacSha1 = crypto.auth.hmac.HmacSha1;

pub const mac_len = 10;
pub const verifier_len = 2;

pub fn saltLen(strength: u8) usize {
    return 4 + 4 * @as(usize, strength);
}

/// The bytes AES adds around the contents: salt, verifier and MAC.
pub fn overhead(strength: u8) usize {
    return saltLen(strength) + verifier_len + mac_len;
}

pub const InitError = error{
    /// AES-192, which std cannot run.
    UnsupportedEncryption,
    /// The password's verifier is not the entry's: the wrong password.
    WrongPassword,
    /// The entry is shorter than its salt, verifier and MAC.
    Invalid,
    Truncated,
    ReadFailed,
};

pub const Error = error{
    /// The contents' HMAC is not the entry's: they were changed, or the
    /// password is wrong in a way the two-byte verifier missed.
    AuthenticationFailed,
    /// The archive ended inside the entry.
    Truncated,
};

const Cipher = union(enum) {
    a128: crypto.core.aes.AesEncryptCtx(crypto.core.aes.Aes128),
    a256: crypto.core.aes.AesEncryptCtx(crypto.core.aes.Aes256),
};

/// The decrypted contents of an entry whose `total` bytes `inner` gives.
/// Initialized in place; must not move while its reader is used.
pub const Reader = struct {
    interface: Io.Reader,
    /// Private: the entry's stored bytes.
    inner: *Io.Reader,
    /// Private: ciphertext bytes still to come.
    left: u64,
    cipher: Cipher,
    mac: HmacSha1,
    counter: u128 = 1,
    keystream: [16]u8 = undefined,
    used: u8 = 16,
    failure: ?Error = null,
    /// Private: staged plaintext, for a decoder that reads it in place.
    staging: [16 * 1024]u8 = undefined,

    pub fn init(r: *Reader, inner: *Io.Reader, total: u64, strength: u8, password: *const aegis.SecretBytes) InitError!void {
        // AES-128 or AES-256; WinZip's 2, AES-192, std has no cipher for.
        const wide = switch (strength) {
            1 => false,
            3 => true,
            else => return error.UnsupportedEncryption,
        };
        const key_len: usize = if (wide) 32 else 16;
        if (total < overhead(strength)) return error.Invalid;
        var salt: [16]u8 = undefined;
        const s = salt[0..saltLen(strength)];
        var verifier: [verifier_len]u8 = undefined;
        readAll(inner, s) catch |e| return e;
        readAll(inner, &verifier) catch |e| return e;
        var keys = aegis.Secret([2 * 32 + verifier_len]u8).init(undefined);
        defer keys.deinit();
        const k = keys.exposeMut()[0 .. 2 * key_len + verifier_len];
        crypto.pwhash.pbkdf2(k, password.expose(), s, 1000, HmacSha1) catch unreachable; // aegis: no-danger: 1,000 rounds and at most 66 bytes are within PBKDF2's bounds, whatever the archive says
        if (!crypto.timing_safe.eql([verifier_len]u8, k[2 * key_len ..][0..verifier_len].*, verifier)) return error.WrongPassword;
        r.* = .{
            .interface = .{ .vtable = &vtable, .buffer = &.{}, .seek = 0, .end = 0 },
            .inner = inner,
            .left = total - overhead(strength),
            .cipher = if (wide) .{ .a256 = .init(k[0..32].*) } else .{ .a128 = .init(k[0..16].*) },
            .mac = .init(k[key_len..][0..key_len]),
        };
        r.interface.buffer = &r.staging;
    }

    /// Erases the keys.
    pub fn deinit(r: *Reader) void {
        crypto.secureZero(u8, std.mem.asBytes(&r.cipher));
        crypto.secureZero(u8, std.mem.asBytes(&r.mac));
        crypto.secureZero(u8, &r.keystream);
    }

    pub fn err(r: *const Reader) ?Error {
        return r.failure;
    }

    const vtable: Io.Reader.VTable = .{ .stream = stream };

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r)); // safe: the vtable is installed only on a Reader's interface
        if (r.left == 0) return r.end();
        const out = limit.min(.limited64(r.left)).slice(try w.writableSliceGreedy(1));
        const n = r.inner.readSliceShort(out) catch return error.ReadFailed;
        if (n == 0) return r.fail(error.Truncated);
        r.mac.update(out[0..n]);
        r.decrypt(out[0..n]);
        r.left -= n;
        w.advance(n);
        return n;
    }

    fn decrypt(r: *Reader, bytes: []u8) void {
        for (bytes) |*b| {
            if (r.used == 16) {
                var block: [16]u8 = undefined;
                std.mem.writeInt(u128, &block, r.counter, .little);
                switch (r.cipher) {
                    inline else => |*c| c.encrypt(&r.keystream, &block),
                }
                r.counter +%= 1;
                r.used = 0;
            }
            b.* ^= r.keystream[r.used];
            r.used += 1;
        }
    }

    /// After the ciphertext: its MAC must be the one computed.
    fn end(r: *Reader) Io.Reader.StreamError {
        if (r.failure != null) return error.ReadFailed;
        var stored: [mac_len]u8 = undefined;
        readAll(r.inner, &stored) catch |e| return switch (e) {
            error.Truncated => r.fail(error.Truncated),
            error.ReadFailed => error.ReadFailed,
        };
        var computed: [HmacSha1.mac_length]u8 = undefined;
        r.mac.final(&computed);
        if (!crypto.timing_safe.eql([mac_len]u8, computed[0..mac_len].*, stored)) return r.fail(error.AuthenticationFailed);
        return error.EndOfStream;
    }

    fn fail(r: *Reader, e: Error) error{ReadFailed} {
        r.failure = e;
        return error.ReadFailed;
    }
};

fn readAll(r: *Io.Reader, out: []u8) error{ Truncated, ReadFailed }!void {
    r.readSliceAll(out) catch |e| return switch (e) {
        error.EndOfStream => error.Truncated,
        error.ReadFailed => error.ReadFailed,
    };
}
