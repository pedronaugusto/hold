//! The one test root: every source's tests, the format tests, the fuzz
//! targets and the interop corpus.
test {
    _ = @import("hold.zig");
    _ = @import("tar/header.zig");
    _ = @import("tar/pax.zig");
    _ = @import("tar/Reader.zig");
    _ = @import("tar/Writer.zig");
    _ = @import("testing/tar_test.zig");
    _ = @import("testing/fuzz_test.zig");
    _ = @import("testing/interop_test.zig");
}
