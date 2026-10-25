//! Where an archive was refused, and why: filled by a reader or extraction
//! given one, alongside the error it returns.
const Diagnostic = @This();

/// The entry being read, counted from zero, header records included in
/// none.
entry: u64 = 0,
/// The archive's byte offset of the header or field at fault.
offset: u64 = 0,
reason: Reason = .none,
/// The method or coder refused, for `unsupported_method`.
method: u64 = 0,

pub const Reason = enum {
    none,
    // Structure.
    checksum,
    truncated,
    header_field,
    pax_record,
    sparse_map,
    trailer,
    signature,
    directory,
    local_header_mismatch,
    overlap,
    extra_field,
    zip64,
    // Bounds.
    header_limit,
    directory_limit,
    entry_limit,
    entries_limit,
    window_limit,
    // Contents.
    size_mismatch,
    crc_mismatch,
    authentication,
    codec,
    // Features.
    unsupported_method,
    unsupported_encryption,
    unsupported_feature,
    password_required,
    // Names and links, at extraction.
    unsafe_name,
    unsafe_link,
    through_link,
    special,
    /// A file or directory the filesystem failed to write, publish or
    /// sync; the entry is the one it came from.
    filesystem,
};

/// Fills the diagnostic, when there is one.
pub fn set(d: ?*Diagnostic, entry: u64, offset: u64, reason: Reason) void {
    if (d) |p| p.* = .{ .entry = entry, .offset = offset, .reason = reason };
}
