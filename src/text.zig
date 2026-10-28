//! Names as text, through xenoglyph: whether a name a format calls UTF-8
//! is well formed, and a zip name in code page 437 as UTF-8.
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

/// `bytes`, a name in code page 437, as UTF-8 at the end of `out`. Every
/// byte is a character of the code page.
pub fn appendCp437(gpa: std.mem.Allocator, out: *std.ArrayList(u8), bytes: []const u8) std.mem.Allocator.Error!void {
    var w: std.Io.Writer.Allocating = .fromArrayList(gpa, out);
    defer out.* = w.toArrayList();
    _ = xenoglyph.encoding.decode(.cp437, bytes, &w.writer, .{ .bom = .none }) catch |e| return switch (e) {
        error.WriteFailed => error.OutOfMemory,
        error.Malformed => unreachable, // aegis: no-danger: replacement mode writes U+FFFD for a malformed sequence and goes on, and code page 437 has none
    };
}

pub fn isAscii(bytes: []const u8) bool {
    for (bytes) |c| if (c >= 0x80) return false;
    return true;
}

test appendCp437 {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try appendCp437(gpa, &out, "File 2 - \x94.txt");
    try appendCp437(gpa, &out, "\x84\xe1");
    try std.testing.expectEqualStrings("File 2 - \u{f6}.txt\u{e4}\u{df}", out.items);
}

test validUtf8 {
    try std.testing.expect(validUtf8("d\u{e9}.txt"));
    try std.testing.expect(validUtf8("\u{fffd}"));
    try std.testing.expect(!validUtf8("d\xe9.txt"));
    try std.testing.expect(!validUtf8("\xe4\xb8a"));
}
