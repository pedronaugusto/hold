//! Names as text, through xenoglyph: whether a name a format calls UTF-8
//! is well formed.
const std = @import("std");
const xenoglyph = @import("xenoglyph");

/// Whether `bytes` are well-formed UTF-8: xenoglyph decodes an ill-formed
/// subpart as U+FFFD, which is told from a real U+FFFD by its bytes.
pub fn validUtf8(bytes: []const u8) bool {
    var at: usize = 0;
    while (at < bytes.len) {
        const d = xenoglyph.utf8.decode(bytes[at..]);
        if (d.code_point == xenoglyph.utf8.replacement and !std.mem.startsWith(u8, bytes[at..], "\u{fffd}")) return false;
        at += d.len;
    }
    return true;
}

pub fn isAscii(bytes: []const u8) bool {
    for (bytes) |c| if (c >= 0x80) return false;
    return true;
}

test validUtf8 {
    try std.testing.expect(validUtf8("d\u{e9}.txt"));
    try std.testing.expect(validUtf8("\u{fffd}"));
    try std.testing.expect(!validUtf8("d\xe9.txt"));
    try std.testing.expect(!validUtf8("\xe4\xb8a"));
}
