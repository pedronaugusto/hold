#!/bin/sh
# Writes testdata.zig, the index the interop tests embed: each archive
# with its `.hold` manifest where there is one, else libarchive's.
set -eu
cd "$(dirname "$0")"
block() {
  echo ""
  echo "pub const $1 = [_]Case{"
  shift
  for f in $(ls "$@" 2>/dev/null | LC_ALL=C sort); do
    m=$f.manifest
    [ -f "$f.hold" ] && m=$f.hold
    echo "    .{ .name = \"$f\", .archive = @embedFile(\"$f\"), .manifest = @embedFile(\"$m\") },"
  done
  echo "};"
}
{
  cat <<'ZIG'
//! Archives other tools wrote, embedded for the interop tests, each with
//! the manifest libarchive 3.8.9 reads from it (testdata/tools/manifest.c),
//! or, where hold reads it otherwise on purpose, the manifest hold reads
//! and why (`.hold`). testdata/README.md says where each came from.
//! Written by index.sh.

pub const Case = struct { name: []const u8, archive: []const u8, manifest: []const u8 };
ZIG
  block tar libarchive/*.tar tar/*.tar
  block zip libarchive/*.zip libarchive/*.zipx zip/*.zip
  block sevenz libarchive/*.7z sevenz/*.7z
  cat <<'ZIG'

/// git's own archives of one tree (git/make.sh): hold's writers must give
/// them byte for byte.
pub const git = struct {
    pub const tar = @embedFile("git/tree.tar");
    pub const zip_store = @embedFile("git/tree-store.zip");
};
ZIG
} > testdata.zig
