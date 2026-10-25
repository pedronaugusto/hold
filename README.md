# hold

hold reads and writes archives in Zig: tar (v7, ustar, pax and GNU, sparse
files included) both ways, zip both ways, and 7z for reading. It streams one
entry at a time over `std.Io.Reader` and `std.Io.Writer` and never holds a
whole archive or a whole entry. Compression comes from
[warp](https://github.com/pedronaugusto/warp), and extraction writes files
through [airlock](https://github.com/pedronaugusto/airlock), with the
hostile-input rules on by default.

Work in progress: tar, zip, 7z reading and extraction are built; most 7z
archives wait on warp's LZMA (7-Zip encodes the header with it).

## Install

Requires Zig 0.17.0. Fetch with `zig fetch --save
git+https://github.com/pedronaugusto/hold`, then obtain the `hold` module
through `b.dependency` and add it to your executable's imports.

## Usage

<!-- BEGIN GENERATED zig build docs -- usage -->
```zig
const hold = @import("hold");

// Write a tar archive: pax where a name or number needs it.
var archive: std.Io.Writer.Allocating = .init(gpa);
defer archive.deinit();
var tw: hold.tar.Writer = .init(&archive.writer, &.{}, .{});
try tw.add(.{ .entry = .{ .name = "hello.txt", .mode = 0o644 } }, "hello, world\n");
try tw.finish();

// Read it back, an entry at a time.
var input: std.Io.Reader = .fixed(archive.written());
var tr: hold.tar.Reader = .init(gpa, &input, &.{}, .{});
defer tr.deinit();
while (try tr.next()) |entry| {
    var buffer: [64]u8 = undefined;
    var contents: std.Io.Writer = .fixed(&buffer);
    _ = try tr.contents().streamRemaining(&contents);
    std.debug.assert(std.mem.eql(u8, entry.name, "hello.txt"));
    std.debug.assert(std.mem.eql(u8, contents.buffered(), "hello, world\n"));
}
```
<!-- END GENERATED -->

## Design

[docs/design.md](docs/design.md) holds the architecture and the
hostile-input rules.

## Scope

- **tar**: reads v7, ustar, pax (local and global headers, extended
  attributes), GNU (long names and links, base-256 numbers, old sparse
  files) and sparse files in pax 0.0, 0.1 and 1.0. Writes ustar, pax and
  GNU. Every header field can be set, so another writer's bytes can be
  reproduced exactly. Sparse files are not written.
- **zip**: reads through the central directory or forward, ZIP64 and data
  descriptors both ways, Info-ZIP's Unicode path, Unix and timestamp fields
  and NTFS times; entries whose data overlap are refused. WinZip AES (128-
  and 256-bit) is read; ZipCrypto, PKWARE's strong encryption and AES-192 are
  refused by name, and nothing is written encrypted. Methods: stored,
  DEFLATE and zstd today, the others as warp gains them (bzip2 read only).
- **7z**: read: encoded headers, solid folders of chained coders, empty
  streams and files, anti items, times and attributes, CRCs; 7z AES read
  with a password. Coders: copy, DEFLATE and zstd today; LZMA, LZMA2,
  bzip2, Deflate64 and the BCJ and Delta filters as warp gains them. PPMd,
  BCJ2 and self-extracting archives are refused.
- **Extraction**: `hold.extract` writes any of them into a directory with
  the hostile-input rules on: names checked, no write through a link,
  links last and only inside, specials refused, permissions as Python's
  `data` filter, a total bound, files through airlock.

## Built with

[aegis](https://github.com/pedronaugusto/aegis) (units and bounds),
[warp](https://github.com/pedronaugusto/warp) (codecs),
[airlock](https://github.com/pedronaugusto/airlock) (durable files),
[xenoglyph](https://github.com/pedronaugusto/xenoglyph) (names as text).
Tested with [shakedown](https://github.com/pedronaugusto/shakedown) and gated
by [preflight](https://github.com/pedronaugusto/preflight).

## Testing

`bay test` runs the suite, the fuzz targets over their corpora and the
example. `bay parsers --fuzz` fuzzes every parser. The interop corpus under
`testdata/` was written by the rivals' own tools, and every archive in it must
read to the entries and bytes libarchive reads (testdata/README.md);
`testdata/interop.sh` has GNU tar, libarchive, Python, Go and 7-Zip read what
hold writes.

`bay bench` times reading and writing tar, zip and 7z through shakedown.
`bench/rivals.sh` times libarchive and Go on the same rows over the same
files and prints the comparison.

## Licence

MIT.
