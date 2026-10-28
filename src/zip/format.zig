//! The zip records (APPNOTE 6.3.10): local headers, central directory
//! records, data descriptors, the end records and ZIP64's, the extra
//! fields hold reads and writes, and DOS times.
const std = @import("std");
const Io = std.Io;
const time = @import("../time.zig");

pub const local_sig: u32 = 0x04034b50;
pub const central_sig: u32 = 0x02014b50;
pub const descriptor_sig: u32 = 0x08074b50;
pub const end_sig: u32 = 0x06054b50;
pub const end64_sig: u32 = 0x06064b50;
pub const locator64_sig: u32 = 0x07064b50;

pub const local_len = 30;
pub const central_len = 46;
pub const end_len = 22;
pub const end64_len = 56;
pub const locator64_len = 20;

/// The general-purpose flags hold reads.
pub const Flags = struct {
    pub const encrypted: u16 = 1 << 0;
    /// Method 14: an end marker ends the stream.
    pub const lzma_eos: u16 = 1 << 1;
    pub const descriptor: u16 = 1 << 3;
    pub const strong_encryption: u16 = 1 << 6;
    pub const utf8: u16 = 1 << 11;
    /// The local header's fields are masked (central directory
    /// encryption).
    pub const masked: u16 = 1 << 13;
};

/// The system a "version made by" names, where it decides how the
/// external attributes read.
pub const Host = enum(u8) {
    dos = 0,
    unix = 3,
    ntfs = 10,
    vfat = 14,
    osx = 19,
    _,

    /// Whether the external attributes' high 16 bits are a Unix mode.
    pub fn unixMode(h: Host) bool {
        return h == .unix or h == .osx;
    }
};

/// Little-endian fields of a record read in place.
pub const Fields = struct {
    bytes: []const u8,
    at: usize = 0,

    pub fn int(f: *Fields, comptime T: type) T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        const v = std.mem.readInt(T, f.bytes[f.at..][0..n], .little);
        f.at += n;
        return v;
    }

    pub fn take(f: *Fields, n: usize) []const u8 {
        const s = f.bytes[f.at..][0..n];
        f.at += n;
        return s;
    }
};

/// A central directory record's fixed part.
pub const Central = struct {
    made_by: u16,
    needed: u16,
    flags: u16,
    method: u16,
    dos_time: u16,
    dos_date: u16,
    crc: u32,
    compressed: u32,
    size: u32,
    name_len: u16,
    extra_len: u16,
    comment_len: u16,
    disk: u16,
    internal: u16,
    external: u32,
    offset: u32,

    pub fn parse(b: *const [central_len]u8) Central {
        var f: Fields = .{ .bytes = b, .at = 4 };
        return .{
            .made_by = f.int(u16),
            .needed = f.int(u16),
            .flags = f.int(u16),
            .method = f.int(u16),
            .dos_time = f.int(u16),
            .dos_date = f.int(u16),
            .crc = f.int(u32),
            .compressed = f.int(u32),
            .size = f.int(u32),
            .name_len = f.int(u16),
            .extra_len = f.int(u16),
            .comment_len = f.int(u16),
            .disk = f.int(u16),
            .internal = f.int(u16),
            .external = f.int(u32),
            .offset = f.int(u32),
        };
    }
};

/// A local header's fixed part.
pub const Local = struct {
    needed: u16,
    flags: u16,
    method: u16,
    dos_time: u16,
    dos_date: u16,
    crc: u32,
    compressed: u32,
    size: u32,
    name_len: u16,
    extra_len: u16,

    pub fn parse(b: *const [local_len]u8) Local {
        var f: Fields = .{ .bytes = b, .at = 4 };
        return .{
            .needed = f.int(u16),
            .flags = f.int(u16),
            .method = f.int(u16),
            .dos_time = f.int(u16),
            .dos_date = f.int(u16),
            .crc = f.int(u32),
            .compressed = f.int(u32),
            .size = f.int(u32),
            .name_len = f.int(u16),
            .extra_len = f.int(u16),
        };
    }
};

/// The end of central directory record.
pub const End = struct {
    disk: u16,
    dir_disk: u16,
    disk_entries: u16,
    entries: u16,
    dir_size: u32,
    dir_offset: u32,
    comment_len: u16,

    pub fn parse(b: *const [end_len]u8) End {
        var f: Fields = .{ .bytes = b, .at = 4 };
        return .{
            .disk = f.int(u16),
            .dir_disk = f.int(u16),
            .disk_entries = f.int(u16),
            .entries = f.int(u16),
            .dir_size = f.int(u32),
            .dir_offset = f.int(u32),
            .comment_len = f.int(u16),
        };
    }
};

/// ZIP64's end record, the fields hold reads.
pub const End64 = struct {
    disk: u32,
    dir_disk: u32,
    entries: u64,
    dir_size: u64,
    dir_offset: u64,

    pub fn parse(b: *const [end64_len]u8) End64 {
        var f: Fields = .{ .bytes = b, .at = 16 };
        const disk = f.int(u32);
        const dir_disk = f.int(u32);
        _ = f.int(u64); // entries on this disk
        return .{ .disk = disk, .dir_disk = dir_disk, .entries = f.int(u64), .dir_size = f.int(u64), .dir_offset = f.int(u64) };
    }
};

//=========================================================================
// Extra fields

pub const Extra = struct {
    pub const zip64: u16 = 0x0001;
    pub const ntfs: u16 = 0x000a;
    pub const unix_time: u16 = 0x5455;
    pub const unicode_path: u16 = 0x7075;
    pub const unix_ids: u16 = 0x7875;
    /// Info-ZIP's original Unix field ("UX"): access and modification
    /// times, and in a local header 16-bit owner ids.
    pub const unix_old: u16 = 0x5855;
    pub const aes: u16 = 0x9901;
};

pub const ExtraError = error{InvalidExtra};

/// The fields of an extra block: (id, data) in order.
pub const ExtraIterator = struct {
    bytes: []const u8,
    at: usize = 0,

    pub const Field = struct { id: u16, data: []const u8 };

    pub fn next(it: *ExtraIterator) ExtraError!?Field {
        if (it.at == it.bytes.len) return null;
        // Some writers pad the block with fewer than four bytes; they hold
        // no field.
        if (it.bytes.len - it.at < 4) {
            it.at = it.bytes.len;
            return null;
        }
        const id = std.mem.readInt(u16, it.bytes[it.at..][0..2], .little);
        const len = std.mem.readInt(u16, it.bytes[it.at + 2 ..][0..2], .little);
        if (it.bytes.len - it.at - 4 < len) return error.InvalidExtra;
        const data = it.bytes[it.at + 4 ..][0..len];
        it.at += 4 + len;
        return .{ .id = id, .data = data };
    }
};

/// The data of the first field with `id`.
pub fn findExtra(bytes: []const u8, id: u16) ExtraError!?[]const u8 {
    var it: ExtraIterator = .{ .bytes = bytes };
    while (try it.next()) |field| if (field.id == id) return field.data;
    return null;
}

/// ZIP64's values, each present only where its 32-bit field is
/// 0xffffffff (or its 16-bit disk 0xffff), in the order size, compressed,
/// offset, disk (APPNOTE 4.5.3).
pub const Zip64 = struct {
    size: ?u64 = null,
    compressed: ?u64 = null,
    offset: ?u64 = null,

    pub fn parse(data: []const u8, want_size: bool, want_compressed: bool, want_offset: bool) ExtraError!Zip64 {
        var z: Zip64 = .{};
        var at: usize = 0;
        inline for (.{ .{ want_size, "size" }, .{ want_compressed, "compressed" }, .{ want_offset, "offset" } }) |w| {
            if (w[0]) {
                if (data.len - at < 8) return error.InvalidExtra;
                @field(z, w[1]) = std.mem.readInt(u64, data[at..][0..8], .little);
                at += 8;
            }
        }
        return z;
    }
};

/// Info-ZIP's extended timestamp (0x5455): its modification time, when it
/// has one. A central record's carries only that time.
pub fn unixMtime(data: []const u8) ?i64 {
    if (data.len < 5 or data[0] & 1 == 0) return null;
    return std.mem.readInt(i32, data[1..5], .little);
}

/// The extended timestamp's times: a local header's carries each its
/// flags name, a central record's only the modification time.
pub fn unixTimes(data: []const u8) struct { mtime: ?i64 = null, atime: ?i64 = null, ctime: ?i64 = null } {
    if (data.len < 1) return .{};
    const flags = data[0];
    var at: usize = 1;
    var t: [3]?i64 = .{ null, null, null };
    for (0..3) |i| {
        if (flags & (@as(u8, 1) << @intCast(i)) == 0) continue;
        if (data.len - at < 4) break;
        t[i] = std.mem.readInt(i32, data[at..][0..4], .little);
        at += 4;
    }
    return .{ .mtime = t[0], .atime = t[1], .ctime = t[2] };
}

/// The original Unix field's (0x5855) times and, in a local header, ids.
pub fn unixOld(data: []const u8) ?struct { atime: i64, mtime: i64, uid: ?u64, gid: ?u64 } {
    if (data.len < 8) return null;
    const atime = std.mem.readInt(i32, data[0..4], .little);
    const mtime = std.mem.readInt(i32, data[4..8], .little);
    if (data.len < 12) return .{ .atime = atime, .mtime = mtime, .uid = null, .gid = null };
    return .{ .atime = atime, .mtime = mtime, .uid = std.mem.readInt(u16, data[8..10], .little), .gid = std.mem.readInt(u16, data[10..12], .little) };
}

/// The NTFS field's (0x000a) modification time, in seconds and
/// nanoseconds since 1970.
pub fn ntfsMtime(data: []const u8) ?Io.Timestamp {
    var at: usize = 4; // reserved
    while (data.len - at >= 4) {
        const tag = std.mem.readInt(u16, data[at..][0..2], .little);
        const len = std.mem.readInt(u16, data[at + 2 ..][0..2], .little);
        at += 4;
        if (data.len - at < len) return null;
        if (tag == 1 and len >= 8) {
            const ticks = std.mem.readInt(u64, data[at..][0..8], .little);
            return time.fromFiletime(ticks);
        }
        at += len;
    }
    return null;
}

/// Info-ZIP's Unicode path (0x7075): its UTF-8 name, when the CRC-32 it
/// records is the header name's (otherwise the name was changed by a tool
/// that left the field stale, and it is ignored).
pub fn unicodePath(data: []const u8, header_name: []const u8) ?[]const u8 {
    if (data.len < 5 or data[0] != 1) return null;
    const crc = std.mem.readInt(u32, data[1..5], .little);
    if (crc != @import("warp").crc32(0, header_name)) return null;
    return data[5..];
}

/// Info-ZIP's Unix ids (0x7875, version 1): uid and gid of any width.
pub fn unixIds(data: []const u8) ?struct { uid: u64, gid: u64 } {
    if (data.len < 3 or data[0] != 1) return null;
    const uid_len = data[1];
    if (uid_len > 8 or data.len < 3 + uid_len) return null;
    const gid_len = data[2 + uid_len];
    if (gid_len > 8 or data.len < 3 + uid_len + gid_len) return null;
    var uid: u64 = 0;
    for (0..uid_len) |i| uid |= @as(u64, data[2 + i]) << @intCast(8 * i);
    var gid: u64 = 0;
    for (0..gid_len) |i| gid |= @as(u64, data[3 + uid_len + i]) << @intCast(8 * i);
    return .{ .uid = uid, .gid = gid };
}

/// WinZip's AES field (0x9901).
pub const Aes = struct {
    /// AE-1 keeps the CRC-32; AE-2 sets it to zero.
    version: u16,
    /// 1, 2, 3: 128, 192, 256-bit keys.
    strength: u8,
    /// The method the contents were compressed with before encryption.
    method: u16,

    pub fn parse(data: []const u8) ?Aes {
        if (data.len < 7 or data[2] != 'A' or data[3] != 'E') return null;
        const a: Aes = .{
            .version = std.mem.readInt(u16, data[0..2], .little),
            .strength = data[4],
            .method = std.mem.readInt(u16, data[5..7], .little),
        };
        if (a.version != 1 and a.version != 2) return null;
        if (a.strength < 1 or a.strength > 3) return null;
        return a;
    }
};

//=========================================================================
// DOS times

/// A DOS date and time (local time by the format, two-second steps) read
/// as UTC: zip gives no zone, and Go reads it so; an extended timestamp
/// or an NTFS time, when present, is the real one.
pub fn fromDos(date: u16, of_day: u16) Io.Timestamp {
    const year: i64 = 1980 + @as(i64, date >> 9);
    const month: i64 = std.math.clamp(@as(i64, (date >> 5) & 0xf), 1, 12);
    const day: i64 = std.math.clamp(@as(i64, date & 0x1f), 1, 31);
    const hour: i64 = @min(@as(i64, of_day >> 11), 23);
    const minute: i64 = @min(@as(i64, (of_day >> 5) & 0x3f), 59);
    const second: i64 = @min(@as(i64, of_day & 0x1f) * 2, 59);
    const days = daysFromCivil(year, month, day);
    return time.fromSeconds(((days * 24 + hour) * 60 + minute) * 60 + second);
}

/// A timestamp as a DOS date and time, in UTC; before 1980 it is 1980's
/// first second, past 2107 the last DOS time.
pub fn toDos(t: Io.Timestamp) struct { date: u16, time: u16 } {
    const secs: i64 = @intCast(std.math.clamp(time.wholeSeconds(t), 315532800, 4354819198));
    const days = @divFloor(secs, 86400);
    const rem = secs - days * 86400;
    const civil = civilFromDays(days);
    return .{
        .date = @intCast(((civil.year - 1980) << 9) | (civil.month << 5) | civil.day),
        .time = @intCast((@divFloor(rem, 3600) << 11) | (@divFloor(@mod(rem, 3600), 60) << 5) | @divFloor(@mod(rem, 60), 2)),
    };
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = @mod(month + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn civilFromDays(days: i64) struct { year: i64, month: i64, day: i64 } {
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const day = doy - @divFloor(153 * mp + 2, 5) + 1;
    const month = if (mp < 10) mp + 3 else mp - 9;
    return .{ .year = yoe + era * 400 + @intFromBool(month <= 2), .month = month, .day = day };
}

test "DOS times round-trip" {
    const t: Io.Timestamp = .{ .nanoseconds = 1_577_934_244 * std.time.ns_per_s }; // 2020-01-02 03:04:04
    const d = toDos(t);
    try std.testing.expectEqual(t.nanoseconds, fromDos(d.date, d.time).nanoseconds);
    const early = toDos(.{ .nanoseconds = 0 });
    try std.testing.expectEqual(@as(i96, 315532800) * std.time.ns_per_s, fromDos(early.date, early.time).nanoseconds);
}

test "extra fields" {
    const block = [_]u8{ 0x55, 0x54, 5, 0, 1, 0x10, 0x32, 0x54, 0x76, 0, 0, 0 };
    try std.testing.expectEqual(@as(?i64, 0x76543210), unixMtime((try findExtra(&block, Extra.unix_time)).?));
    var bad: ExtraIterator = .{ .bytes = &[_]u8{ 1, 0, 9, 0, 1 } };
    try std.testing.expectError(error.InvalidExtra, bad.next());
}
