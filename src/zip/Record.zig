//! A zip entry as its central directory record (or, read forward, its
//! local header) describes it: the common entry and what only zip has.
//! Slices borrow from the reader that made it.
const Record = @This();

const Entry = @import("../Entry.zig");
const format = @import("format.zig");
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
made_by: u16 = 0,
needed: u16,
internal: u16 = 0,
external: u32 = 0,
dos_date: u16,
dos_time: u16,
/// The name's bytes as the header holds them (the common entry's name may
/// come from a Unicode path field instead).
raw_name: []const u8,
extra: []const u8,
comment: []const u8 = "",
encryption: Encryption = .none,
/// AES's strength (1, 2, 3) and version (1 for AE-1, 2 for AE-2).
aes: ?format.Aes = null,

/// The common entry's fields from a record's: name and encoding, kind,
/// mode, owner and times.
pub fn describe(r: *Record) void {
    const host: format.Host = @fromBackingInt(@intCast(r.made_by >> 8));
    const e = &r.entry;
    e.name = r.raw_name;
    e.encoding = if (r.flags & format.Flags.utf8 != 0 or isAscii(r.raw_name)) .utf8 else .cp437;
    if (format.findExtra(r.extra, format.Extra.unicode_path) catch null) |data| {
        if (format.unicodePath(data, r.raw_name)) |name| {
            e.name = name;
            e.encoding = .utf8;
        }
    }
    const unix = r.external >> 16;
    e.kind = .file;
    if (host.unixMode() and unix != 0) {
        e.mode = unix & 0o7777;
        // zip has no device numbers: a device or a pipe in its mode is
        // what the writer read its contents from (Info-ZIP archiving its
        // standard input records a pipe), and the entry is a file.
        e.kind = switch (unix & 0o170000) {
            0o040000 => .directory,
            0o120000 => .symlink,
            else => .file,
        };
    }
    if (e.kind == .file and ((e.name.len != 0 and e.name[e.name.len - 1] == '/') or r.external & 0x10 != 0)) e.kind = .directory;
    if (format.findExtra(r.extra, format.Extra.unix_ids) catch null) |data| {
        if (format.unixIds(data)) |ids| {
            e.uid = ids.uid;
            e.gid = ids.gid;
        }
    }
    e.mtime = format.fromDos(r.dos_date, r.dos_time);
    if (format.findExtra(r.extra, format.Extra.ntfs) catch null) |data| {
        if (format.ntfsMtime(data)) |t| e.mtime = t;
    }
    if (format.findExtra(r.extra, format.Extra.unix_old) catch null) |data| {
        if (format.unixOld(data)) |u| {
            e.mtime = Entry.seconds(u.mtime);
            e.atime = Entry.seconds(u.atime);
        }
    }
    if (format.findExtra(r.extra, format.Extra.unix_time) catch null) |data| {
        if (format.unixMtime(data)) |s| e.mtime = Entry.seconds(s);
    }
    if (r.flags & format.Flags.encrypted != 0) {
        r.encryption = if (r.flags & format.Flags.strong_encryption != 0) .strong else .zipcrypto;
        if (@backingInt(r.method) == @backingInt(Method.aes)) {
            if (format.findExtra(r.extra, format.Extra.aes) catch null) |data| {
                if (format.Aes.parse(data)) |a| {
                    r.encryption = .aes;
                    r.aes = a;
                    r.method = @fromBackingInt(@intCast(a.method));
                }
            }
        }
    }
}

fn isAscii(s: []const u8) bool {
    for (s) |c| if (c >= 0x80) return false;
    return true;
}
