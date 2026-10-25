//! The names an extraction writes (design §3.1): relative, `/`-separated
//! and normalized, every way out of the destination refused. Reading never
//! rewrites a name; this is the separate check extraction makes.
const std = @import("std");
const builtin = @import("builtin");

pub const CheckError = error{
    /// An absolute path, a drive or UNC prefix, a `..` component, a NUL,
    /// a backslash, an empty name, a name past `max_len`, or on Windows a
    /// reserved name or a component ending in a dot or a space.
    UnsafeName,
};

/// The longest name checked: past it, no filesystem takes the path.
pub const max_len = 4096;

/// `raw` normalized into `buffer`: empty and `.` components dropped, no
/// trailing `/`. Null for a name that is the destination itself (`./`).
/// The rules are the same on every OS but Windows' own reserved names,
/// since an archive crosses systems: a backslash is a separator on
/// Windows, so `..\x` is a way out there and is refused everywhere (Go's
/// rule for zip).
pub fn check(raw: []const u8, buffer: *[max_len]u8) CheckError!?[]const u8 {
    if (raw.len == 0 or raw.len > max_len) return error.UnsafeName;
    if (raw[0] == '/') return error.UnsafeName;
    if (std.mem.findScalar(u8, raw, 0) != null or std.mem.findScalar(u8, raw, '\\') != null) return error.UnsafeName;
    // A drive letter, as Windows reads one anywhere a path starts.
    if (raw.len >= 2 and raw[1] == ':' and std.ascii.isAlphabetic(raw[0])) return error.UnsafeName;
    var len: usize = 0;
    var it = std.mem.splitScalar(u8, raw, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) return error.UnsafeName;
        if (builtin.os.tag == .windows and windowsReserved(part)) return error.UnsafeName;
        if (len != 0) {
            buffer[len] = '/';
            len += 1;
        }
        @memcpy(buffer[len..][0..part.len], part);
        len += part.len;
    }
    if (len == 0) return null;
    return buffer[0..len];
}

/// A component Windows would read as something else: a device name with
/// any extension, a colon (a stream name), or a trailing dot or space,
/// which Windows strips.
fn windowsReserved(part: []const u8) bool {
    if (part[part.len - 1] == '.' or part[part.len - 1] == ' ') return true;
    if (std.mem.findScalar(u8, part, ':') != null) return true;
    const stem = part[0 .. std.mem.findScalar(u8, part, '.') orelse part.len];
    const devices = [_][]const u8{ "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" };
    for (devices) |d| if (std.ascii.eqlIgnoreCase(stem, d)) return true;
    if (stem.len == 4 and std.ascii.isDigit(stem[3]) and stem[3] != '0') {
        if (std.ascii.eqlIgnoreCase(stem[0..3], "COM") or std.ascii.eqlIgnoreCase(stem[0..3], "LPT")) return true;
    }
    return false;
}

pub const LinkError = error{
    /// An absolute target, a `..` after a named component, or more leading
    /// `..` than the link's directory is deep.
    UnsafeLink,
};

/// Whether a symbolic link at `path` (checked) with `target` stays inside
/// the destination however it is followed: the target is relative, its
/// `..` components only lead it (one after a named component could climb
/// out of a directory that is itself a link), and they climb no higher
/// than the link's directory is deep.
pub fn checkLink(path: []const u8, target: []const u8) LinkError!void {
    if (target.len == 0 or target[0] == '/') return error.UnsafeLink;
    if (std.mem.findScalar(u8, target, 0) != null or std.mem.findScalar(u8, target, '\\') != null) return error.UnsafeLink;
    if (target.len >= 2 and target[1] == ':' and std.ascii.isAlphabetic(target[0])) return error.UnsafeLink;
    const depth = std.mem.countScalar(u8, path, '/');
    var ups: usize = 0;
    var named = false;
    var it = std.mem.splitScalar(u8, target, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (named) return error.UnsafeLink;
            ups += 1;
            if (ups > depth) return error.UnsafeLink;
        } else named = true;
    }
}

test check {
    var buf: [max_len]u8 = undefined;
    try std.testing.expectEqualStrings("a/b", (try check("./a//b/", &buf)).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try check("./", &buf));
    for ([_][]const u8{ "/etc/passwd", "../x", "a/../../x", "a/..", "C:x", "c:/x", "a\\..\\x", "a\x00b", "" }) |bad| {
        try std.testing.expectError(error.UnsafeName, check(bad, &buf));
    }
}

test checkLink {
    try checkLink("a/b/link", "../c");
    try checkLink("a/b/link", "../../c");
    try checkLink("link", "a/b");
    try std.testing.expectError(error.UnsafeLink, checkLink("link", "../x"));
    try std.testing.expectError(error.UnsafeLink, checkLink("a/link", "../../x"));
    try std.testing.expectError(error.UnsafeLink, checkLink("link", "/etc"));
    // Through another link: `sub/l` may itself point anywhere inside.
    try std.testing.expectError(error.UnsafeLink, checkLink("l2", "sub/l/.."));
}
