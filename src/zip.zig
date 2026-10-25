//! zip: read through the central directory (`Archive`) or forward
//! (`Stream`), written by `Writer`; ZIP64, data descriptors, Info-ZIP's
//! fields, WinZip AES read; methods through warp.

/// Reads an archive through its central directory.
pub const Archive = @import("zip/Archive.zig");
/// Reads an archive forward by its local headers.
pub const Stream = @import("zip/Stream.zig");
/// Writes an archive.
pub const Writer = @import("zip/Writer.zig");
/// An entry as zip describes it.
pub const Record = @import("zip/Record.zig");
/// A compression method by zip's numbering.
pub const Method = @import("codec.zig").Method;
