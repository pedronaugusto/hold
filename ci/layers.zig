//! Source layers, lowest first. Every production source has one place.
const gantry = @import("gantry");

pub const layers: []const gantry.rules.Layer = &.{
    .{ .name = "entries and bounds", .patterns = &.{
        "src/Entry.zig",
        "src/Limits.zig",
        "src/Diagnostic.zig",
        "src/text.zig",
        "src/name.zig",
    } },
    .{ .name = "streams and codecs", .patterns = &.{
        "src/source.zig",
        "src/Bounded.zig",
        "src/Checked.zig",
        "src/codec.zig",
    } },
    .{ .name = "tar fields", .patterns = &.{
        "src/tar/header.zig",
        "src/tar/pax.zig",
    } },
    .{ .name = "tar", .patterns = &.{
        "src/tar/Reader.zig",
        "src/tar/Writer.zig",
    } },
    .{ .name = "zip records", .patterns = &.{
        "src/zip/format.zig",
        "src/zip/aes.zig",
    } },
    .{ .name = "zip entries", .patterns = &.{"src/zip/Record.zig"} },
    .{ .name = "zip", .patterns = &.{
        "src/zip/Archive.zig",
        "src/zip/Stream.zig",
        "src/zip/Writer.zig",
    } },
    .{ .name = "7z header", .patterns = &.{
        "src/sevenz/header.zig",
        "src/sevenz/aes.zig",
    } },
    .{ .name = "7z", .patterns = &.{"src/sevenz/Archive.zig"} },
    .{ .name = "formats", .patterns = &.{
        "src/tar.zig",
        "src/zip.zig",
        "src/sevenz.zig",
    } },
    .{ .name = "extraction", .patterns = &.{"src/extract.zig"} },
    .{ .name = "public", .patterns = &.{"src/hold.zig"} },
};

pub const entries: []const []const u8 = &.{};

pub const modules: []const gantry.NamedModule = &.{};

const package_references = [_]gantry.rules.ReferenceRule{
    .{ .name = "named dependencies", .unresolved_only = true, .except_targets = &.{
        "std",
        "builtin",
        "aegis",
        "warp",
        "airlock",
        "xenoglyph",
        "shakedown",
        "testdata",
        "hold",
        "preflight_bench_options",
    } },
    .{ .name = "source siblings", .suffix = ".zig", .relative = true, .except_targets = &.{"src/**"} },
};

pub const references: []const gantry.rules.ReferenceRule = &package_references;
pub const owned: []const gantry.rules.TokenRule = &.{};

pub const required = [_][]const u8{
    "src/hold.zig",
    "src/tests.zig",
};
