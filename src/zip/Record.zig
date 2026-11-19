//! A zip entry as its central directory record (or, read forward, its
//! local header) describes it: the common entry and what only zip has.
//! Slices borrow from the reader that made it.
const Record = @This();

const aegis = @import("aegis");
const Entry = @import("../Entry.zig");
const format = @import("format.zig");
const text = @import("../text.zig");
const Method = @import("../codec.zig").Method;

pub const Encryption = enum {
    none,
    /// WinZip AES, read with a password.
    aes,
    /// Traditional PKWARE encryption: refused (design §0).
    zipcrypto,
    /// PKWARE's strong encryption: refused.
    strong,
};

entry: Entry,
/// The method the contents were stored with: for an AES entry, the one
/// inside the encryption.
method: Method,
flags: u16,
/// The CRC-32 of the contents; zero for an AE-2 entry.
crc: u32,
/// The stored bytes, encryption's overhead included.
compressed: u64,
/// The local header's offset in the archive, any prepended bytes counted.
offset: u64,
/// The writer's host (high byte) and APPNOTE version; null read forward,
/// where a local header names neither.
made_by: ?u16 = null,
needed: u16,
internal: u16 = 0,
external: u32 = 0,
dos_date: u16,
dos_time: u16,
/// The name's bytes as the header holds them (the common entry's name may
/// come from a Unicode path field instead).
raw_name: []const u8,
/// The name is code page 437 (an MS-DOS host, no UTF-8 flag, not
/// well-formed UTF-8, no Unicode path field): the reader gives
/// `entry.name` decoded to UTF-8.
cp437: bool = false,
extra: []const u8,
comment: []const u8 = "",
encryption: Encryption = .none,
/// AES's strength (1, 2, 3) and version (1 for AE-1, 2 for AE-2).
aes: ?format.Aes = null,

/// The extra fields `describe` reads, each the first of its id.
const Found = struct {
    unicode_path: ?[]const u8 = null,
    unix_ids: ?[]const u8 = null,
    ntfs: ?[]const u8 = null,
    unix_old: ?[]const u8 = null,
    unix_time: ?[]const u8 = null,
    aes: ?[]const u8 = null,

    /// The block read once. Its readers refuse an entry whose block holds a
    /// field cut short before they describe it, so every field is whole here.
    fn of(extra: []const u8) Found {
        var found: Found = .{};
        var it: format.ExtraIterator = .{ .bytes = extra };
        while (it.next() catch aegis.assert.never("the reader checked every extra field before describing the entry")) |field| {
            const slot = switch (field.id) {
                format.Extra.unicode_path => &found.unicode_path,
                format.Extra.unix_ids => &found.unix_ids,
                format.Extra.ntfs => &found.ntfs,
                format.Extra.unix_old => &found.unix_old,
                format.Extra.unix_time => &found.unix_time,
                format.Extra.aes => &found.aes,
                else => continue,
            };
            if (slot.* == null) slot.* = field.data;
        }
        return found;
    }
};

/// The common entry's fields from a record's: name and encoding, kind,
/// mode, owner and times.
pub fn describe(r: *Record) void {
    const host: ?format.Host = if (r.made_by) |m| @fromBackingInt(@intCast(m >> 8)) else null;
    const e = &r.entry;
    const found: Found = .of(r.extra);
    e.name = r.raw_name;
    // Without the UTF-8 flag APPNOTE says code page 437, which MS-DOS and
    // Windows writers mean; Info-ZIP and macOS write UTF-8 there, other
    // Unix writers their locale's bytes. As libarchive reads them: a
    // well-formed UTF-8 name is UTF-8, another from an MS-DOS host code
    // page 437 (the reader decodes it), the rest bytes of no named
    // encoding.
    const utf8 = r.flags & format.Flags.utf8 != 0 or text.validUtf8(r.raw_name);
    r.cp437 = !utf8 and host == .dos;
    e.encoding = if (utf8 or r.cp437) .utf8 else .unspecified;
    if (found.unicode_path) |data| {
        if (format.unicodePath(data, r.raw_name)) |name| {
            e.name = name;
            e.encoding = .utf8;
            r.cp437 = false;
        }
    }
    const unix: ?u32 = if (host != null and host.?.unixMode() and r.external >> 16 != 0) r.external >> 16 else null;
    if (unix) |m| e.mode = m & 0o7777;
    e.kind = kindOf(unix, e.name, r.external);
    if (found.unix_ids) |data| {
        if (format.unixIds(data)) |ids| {
            e.uid = ids.uid;
            e.gid = ids.gid;
        }
    }
    e.mtime = format.fromDos(r.dos_date, r.dos_time);
    if (found.ntfs) |data| {
        if (format.ntfsMtime(data)) |t| e.mtime = t;
    }
    if (found.unix_old) |data| {
        if (format.unixOld(data)) |u| {
            e.mtime = Entry.seconds(u.mtime);
            e.atime = Entry.seconds(u.atime);
        }
    }
    if (found.unix_time) |data| {
        if (format.unixMtime(data)) |s| e.mtime = Entry.seconds(s);
    }
    if (r.flags & format.Flags.encrypted != 0) {
        r.encryption = if (r.flags & format.Flags.strong_encryption != 0) .strong else .zipcrypto;
        if (@backingInt(r.method) == @backingInt(Method.aes)) {
            if (found.aes) |data| {
                if (format.Aes.parse(data)) |a| {
                    r.encryption = .aes;
                    r.aes = a;
                    r.method = @fromBackingInt(@intCast(a.method));
                }
            }
        }
    }
}

/// The entry's kind: from a Unix mode where the record has one, else a
/// directory by its name's `/` or the DOS directory attribute. zip has no
/// device numbers: a device or a pipe in a mode is what the writer read
/// its contents from (Info-ZIP archiving its standard input records a
/// pipe), and the entry is a file.
fn kindOf(unix: ?u32, name: []const u8, external: u32) Entry.Kind {
    if (unix) |m| switch (m & 0o170000) {
        0o040000 => return .directory,
        0o120000 => return .symlink,
        else => {},
    };
    const dir = (name.len != 0 and name[name.len - 1] == '/') or external & 0x10 != 0;
    return if (dir) .directory else .file;
}
