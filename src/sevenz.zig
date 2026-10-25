//! 7z, read: the start header, encoded headers, solid folders of chained
//! coders, empty streams and files, anti items, times and attributes,
//! CRCs; 7z AES read with a password; coders through warp.

/// Reads an archive.
pub const Archive = @import("sevenz/Archive.zig");
/// One entry and where its contents are.
pub const Item = Archive.Item;
