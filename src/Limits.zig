//! What an archive may declare before hold refuses it: every length is
//! checked against these before anything is allocated for it (design §3).
//! The defaults refuse only what no real archive needs.
const aegis = @import("aegis");

/// A number of bytes an archive declares.
pub const Bytes = aegis.units.Bytes(u64);
/// A number of entries.
pub const Entries = aegis.units.Count(EntriesTag, u64);
const EntriesTag = struct {};

/// One header record: a pax extended header, a GNU long name or link, a
/// sparse map, a zip extra field block or comment, a link target stored
/// as contents.
header: Bytes = .literal("1MiB"),
/// A zip central directory or a 7z header, held whole while the archive
/// is open.
directory: Bytes = .literal("256MiB"),
/// Entries in one archive.
entries: Entries = .fromRaw(1 << 20),
/// An entry whose size is not declared before its contents (a zip entry
/// streamed with a data descriptor): its contents stop here.
entry: Bytes = .fromRaw(std.math.maxInt(u64)),
/// The history a codec keeps for an entry (a zstd window), allocated when
/// the entry is opened.
window: Bytes = .literal("128MiB"),

/// Whether `n` bytes are past `limit`.
pub fn over(limit: Bytes, n: u64) bool {
    return Bytes.fromRaw(n).compare(limit) == .gt;
}

/// Whether one more entry than `n` would be past `limit`.
pub fn full(limit: Entries, n: u64) bool {
    return Entries.fromRaw(n).compare(limit) != .lt;
}

const std = @import("std");
