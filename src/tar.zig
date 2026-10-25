//! tar: read forward from any reader (v7, ustar, pax, GNU, sparse files),
//! written as ustar, pax or GNU.

/// Reads an archive one entry at a time.
pub const Reader = @import("tar/Reader.zig");
/// Writes an archive one entry at a time.
pub const Writer = @import("tar/Writer.zig");
/// A pax extended header record.
pub const Record = pax.Record;
/// How a header's checksum is spelled when written.
pub const ChecksumStyle = header.ChecksumStyle;

const header = @import("tar/header.zig");
const pax = @import("tar/pax.zig");
