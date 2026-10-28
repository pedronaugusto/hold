//! The 512-byte tar header: its fields' places in every dialect, numbers
//! in octal and base-256, and the checksum.
const std = @import("std");

pub const block_len = 512;
pub const Block = [block_len]u8;

/// A field's place in the block.
pub const Field = struct {
    start: usize,
    len: usize,

    pub fn of(f: Field, b: *const Block) []const u8 {
        return b[f.start..][0..f.len];
    }

    pub fn slot(f: Field, b: *Block) []u8 {
        return b[f.start..][0..f.len];
    }
};

pub const name: Field = .{ .start = 0, .len = 100 };
pub const mode: Field = .{ .start = 100, .len = 8 };
pub const uid: Field = .{ .start = 108, .len = 8 };
pub const gid: Field = .{ .start = 116, .len = 8 };
pub const size: Field = .{ .start = 124, .len = 12 };
pub const mtime: Field = .{ .start = 136, .len = 12 };
pub const chksum: Field = .{ .start = 148, .len = 8 };
pub const typeflag = 156;
pub const linkname: Field = .{ .start = 157, .len = 100 };
pub const magic: Field = .{ .start = 257, .len = 6 };
pub const version: Field = .{ .start = 263, .len = 2 };
pub const uname: Field = .{ .start = 265, .len = 32 };
pub const gname: Field = .{ .start = 297, .len = 32 };
pub const devmajor: Field = .{ .start = 329, .len = 8 };
pub const devminor: Field = .{ .start = 337, .len = 8 };
/// ustar and pax.
pub const prefix: Field = .{ .start = 345, .len = 155 };
/// GNU's own fields where ustar has its prefix.
pub const gnu_atime: Field = .{ .start = 345, .len = 12 };
pub const gnu_ctime: Field = .{ .start = 357, .len = 12 };
/// Old GNU sparse files: four (offset, numbytes) pairs in the header, a
/// flag saying more follow in extension blocks, and the file's real size.
pub const gnu_sparse = 386;
pub const gnu_sparse_entries = 4;
pub const gnu_isextended = 482;
pub const gnu_realsize: Field = .{ .start = 483, .len = 12 };
/// An extension block: 21 pairs and its own flag.
pub const gnu_ext_entries = 21;
pub const gnu_ext_isextended = 504;

/// Which dialect a header is written in, from its magic.
pub const Dialect = enum { v7, ustar, gnu };

pub fn dialect(b: *const Block) Dialect {
    const m = b[257..265];
    if (std.mem.eql(u8, m, "ustar\x0000")) return .ustar;
    if (std.mem.eql(u8, m, "ustar  \x00")) return .gnu;
    // Some writers leave the version blank or as spaces; the magic decides.
    if (std.mem.eql(u8, m[0..6], "ustar\x00")) return .ustar;
    return .v7;
}

/// A string field: up to its first NUL.
pub fn string(field: []const u8) []const u8 {
    return field[0 .. std.mem.findScalar(u8, field, 0) orelse field.len];
}

pub const NumberError = error{InvalidNumber};

/// An unsigned number field: octal, with leading and trailing spaces and
/// NULs, or base-256 (the high bit of its first byte set) as GNU and star
/// write values the octal digits cannot hold. An empty field is zero.
pub fn unsigned(field: []const u8) NumberError!u64 {
    const v = try signed(field);
    if (v < 0) return error.InvalidNumber;
    return @intCast(v);
}

/// A number field that may be negative: a time before 1970 is written in
/// base-256 two's complement.
pub fn signed(field: []const u8) NumberError!i64 {
    if (field.len != 0 and field[0] & 0x80 != 0) {
        // Base-256: big-endian two's complement, the marker bit dropped
        // from a positive value's first byte.
        const negative = field[0] & 0x40 != 0;
        var v: i128 = if (negative) -1 else 0;
        for (field, 0..) |c, i| {
            const byte: u8 = if (i == 0) (if (negative) c | 0x80 else c & 0x7f) else c;
            v = (v << 8) | byte;
            if (v > std.math.maxInt(i64) or v < std.math.minInt(i64)) return error.InvalidNumber;
        }
        return @intCast(v);
    }
    var s = field;
    while (s.len != 0 and (s[0] == ' ' or s[0] == 0)) s = s[1..];
    var end: usize = 0;
    while (end < s.len and s[end] >= '0' and s[end] <= '7') end += 1;
    // What follows the digits may only be spaces and NULs.
    for (s[end..]) |c| if (c != ' ' and c != 0) return error.InvalidNumber;
    var v: u64 = 0;
    for (s[0..end]) |c| {
        if (v > std.math.maxInt(i64) >> 3) return error.InvalidNumber;
        v = (v << 3) | (c - '0');
    }
    return @intCast(v);
}

/// Whether `value` fits the field as octal digits with a terminating NUL.
pub fn fitsOctal(len: usize, value: u64) bool {
    const digits = len - 1;
    if (digits >= 22) return true;
    return value >> @intCast(3 * digits) == 0;
}

/// `value` as zero-padded octal digits and a NUL, filling the field.
pub fn putOctal(field: []u8, value: u64) void {
    std.debug.assert(fitsOctal(field.len, value));
    var v = value;
    var i = field.len - 1;
    field[i] = 0;
    while (i > 0) {
        i -= 1;
        field[i] = '0' + @as(u8, @intCast(v & 7));
        v >>= 3;
    }
}

/// `value` in base-256, filling the field: GNU's form for numbers octal
/// cannot hold, negative times included.
pub fn putBase256(field: []u8, value: i64) void {
    var v: i128 = value;
    var i = field.len;
    while (i > 0) {
        i -= 1;
        field[i] = @truncate(@as(u128, @bitCast(v)));
        v >>= 8;
    }
    field[0] |= 0x80;
}

/// A time's whole seconds, in octal where they fit and base-256 where
/// they do not (GNU's atime and ctime).
pub fn putTime(field: []u8, t: @import("std").Io.Timestamp) void {
    const secs: i64 = @intCast(std.math.clamp(@import("../time.zig").wholeSeconds(t), std.math.minInt(i64), std.math.maxInt(i64)));
    if (secs >= 0 and fitsOctal(field.len, @intCast(secs))) putOctal(field, @intCast(secs)) else putBase256(field, secs);
}

/// How the checksum field is spelled; readers accept either.
pub const ChecksumStyle = enum {
    /// Six octal digits, a NUL and a space: GNU tar, libarchive and Go.
    nul_space,
    /// Seven octal digits and a NUL: git.
    nul,
};

/// The checksum of a header whose checksum field counts as spaces:
/// unsigned bytes, and signed as some historic writers summed them.
pub fn sums(b: *const Block) struct { unsigned: u64, signed: i64 } {
    var u: u64 = 0;
    var s: i64 = 0;
    for (b, 0..) |c, i| {
        const byte: u8 = if (i >= chksum.start and i < chksum.start + chksum.len) ' ' else c;
        u += byte;
        s += @as(i8, @bitCast(byte));
    }
    return .{ .unsigned = u, .signed = s };
}

/// Whether the stored checksum matches the header, either way it was
/// summed.
pub fn checksumValid(b: *const Block) bool {
    const stored = unsigned(chksum.of(b)) catch return false;
    const computed = sums(b);
    return stored == computed.unsigned or @as(i64, @intCast(stored)) == computed.signed;
}

/// Writes the checksum of a header whose other fields are final.
pub fn putChecksum(b: *Block, style: ChecksumStyle) void {
    const sum = sums(b).unsigned;
    const field = chksum.slot(b);
    switch (style) {
        .nul_space => {
            putOctal(field[0..7], sum);
            field[7] = ' ';
        },
        .nul => putOctal(field, sum),
    }
}

pub fn isZero(b: *const Block) bool {
    return std.mem.allEqual(u8, b, 0);
}

/// Where a ustar name splits into prefix and name: the last `/` that
/// leaves at most 155 bytes before it and at most 100 after, or null.
pub fn splitUstar(path: []const u8) ?usize {
    if (path.len <= name.len) return null;
    var i: usize = @min(path.len - 1, prefix.len);
    while (i > 0) : (i -= 1) {
        if (path[i] == '/' and path.len - i - 1 <= name.len and path.len - i - 1 > 0) return i;
    }
    return null;
}

test unsigned {
    try std.testing.expectEqual(@as(u64, 0o644), try unsigned("0000644\x00"));
    try std.testing.expectEqual(@as(u64, 0o644), try unsigned("   644 \x00"));
    try std.testing.expectEqual(@as(u64, 0), try unsigned("\x00\x00\x00\x00"));
    try std.testing.expectError(error.InvalidNumber, unsigned("0000x44\x00"));
    try std.testing.expectEqual(@as(u64, 1 << 32), try unsigned(&[_]u8{ 0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }));
    try std.testing.expectEqual(@as(i64, -1), try signed(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }));
}

test putBase256 {
    var f: [12]u8 = undefined;
    putBase256(&f, -2);
    try std.testing.expectEqual(@as(i64, -2), try signed(&f));
    putBase256(&f, 1 << 40);
    try std.testing.expectEqual(@as(i64, 1 << 40), try signed(&f));
}

test splitUstar {
    const long = rep('a', 120) ++ "/" ++ rep('b', 90);
    try std.testing.expectEqual(@as(?usize, 120), splitUstar(long));
    try std.testing.expectEqual(@as(?usize, null), splitUstar(&rep('a', 101)));
    try std.testing.expectEqual(@as(?usize, null), splitUstar("short"));
}

fn rep(comptime c: u8, comptime n: usize) [n]u8 {
    return @splat(c);
}
