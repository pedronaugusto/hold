//! The one test root: every source's tests, the format tests, the fuzz
//! targets and the interop corpus.
test {
    _ = @import("hold.zig");
    _ = @import("tar/header.zig");
    _ = @import("tar/pax.zig");
    _ = @import("tar/Reader.zig");
    _ = @import("tar/Writer.zig");
    _ = @import("Checked.zig");
    _ = @import("Bounded.zig");
    _ = @import("codec.zig");
    _ = @import("text.zig");
    _ = @import("zip/format.zig");
    _ = @import("zip/Archive.zig");
    _ = @import("zip/Stream.zig");
    _ = @import("zip/Writer.zig");
    _ = @import("zip/aes.zig");
    _ = @import("sevenz/header.zig");
    _ = @import("sevenz/aes.zig");
    _ = @import("sevenz/Archive.zig");
    _ = @import("testing/sevenz_test.zig");
    _ = @import("testing/tar_test.zig");
    _ = @import("testing/zip_test.zig");
    _ = @import("name.zig");
    _ = @import("testing/extract_test.zig");
    _ = @import("testing/fuzz_test.zig");
    _ = @import("testing/interop_test.zig");
}
