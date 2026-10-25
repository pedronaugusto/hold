//! Archive formats, both ways: tar and zip read and written, 7z read.
//! Codecs come from warp, extraction's files from airlock.

/// One entry of an archive, as every format describes one.
pub const Entry = @import("Entry.zig");
/// What an archive may declare before it is refused.
pub const Limits = @import("Limits.zig");
/// Where an archive was refused, and why.
pub const Diagnostic = @import("Diagnostic.zig");
/// tar archives.
pub const tar = @import("tar.zig");
/// zip archives.
pub const zip = @import("zip.zig");
/// 7z archives, read.
pub const sevenz = @import("sevenz.zig");
/// The names extraction writes, and the links it makes.
pub const name = @import("name.zig");
/// Extraction into a directory, with the hostile-input rules on.
pub const extract = @import("extract.zig").extract;
/// Extraction's options, sources, errors and summary.
pub const Extract = @import("extract.zig");
