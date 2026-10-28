//! One entry of an archive, as every format describes one: what the readers
//! hand out and what the writers take. Slices borrow from the reader until
//! its next entry, or from the caller while a writer takes the entry.
const std = @import("std");
const Io = std.Io;
const time = @import("time.zig");

/// What the entry is.
pub const Kind = enum {
    file,
    directory,
    symlink,
    /// A second name for an earlier entry: `link` is that entry's name.
    hardlink,
    character_device,
    block_device,
    fifo,
    /// Something that is no file: a tar volume label, a multi-volume
    /// continuation. Never extracted.
    other,
};

/// How the bytes of `name` and `link` are to be read as text.
pub const Encoding = enum {
    /// UTF-8, as the format says: a pax header's names, a zip name (with
    /// its UTF-8 flag, or well formed, or an MS-DOS host's code page 437
    /// decoded) or a 7z name (decoded from UTF-16LE).
    utf8,
    /// Bytes the format gives no encoding for: a ustar, GNU or v7 name, a
    /// pax name under `hdrcharset=BINARY`, a zip name from another host
    /// that is not UTF-8. By convention the creator's locale, and UTF-8
    /// nearly everywhere.
    unspecified,
};

/// A device's numbers, for `character_device` and `block_device`.
pub const Device = struct { major: u32 = 0, minor: u32 = 0 };

kind: Kind = .file,
/// The entry's name in the archive, unchanged: `/`-separated by every
/// format here, a directory's often ending in `/`. `hold.name.check`
/// gives the name an extraction writes, or why it refuses it.
name: []const u8,
encoding: Encoding = .unspecified,
/// A symbolic link's target, or a hard link's earlier entry.
link: []const u8 = "",
/// The contents' length: what the entry's reader gives, holes of a sparse
/// file included.
size: u64 = 0,
/// Permission bits with the set-user-ID, set-group-ID and sticky bits
/// (0o7777), when the archive has them.
mode: ?u32 = null,
uid: ?u64 = null,
gid: ?u64 = null,
uname: []const u8 = "",
gname: []const u8 = "",
mtime: ?Io.Timestamp = null,
atime: ?Io.Timestamp = null,
/// The inode's change time (tar) or creation time where a format has no
/// change time and says so (`btime`).
ctime: ?Io.Timestamp = null,
btime: ?Io.Timestamp = null,
device: Device = .{},

/// A timestamp from whole seconds since the epoch.
pub fn seconds(s: i64) Io.Timestamp {
    return time.fromSeconds(s);
}
