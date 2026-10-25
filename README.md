# hold

hold reads and writes archives in Zig: tar (v7, ustar, pax and GNU, sparse
files included) both ways, zip both ways, and 7z for reading. It streams one
entry at a time over `std.Io.Reader` and `std.Io.Writer` and never holds a
whole archive or a whole entry. Compression comes from
[warp](https://github.com/pedronaugusto/warp), and extraction writes files
through [airlock](https://github.com/pedronaugusto/airlock), with the
hostile-input rules on by default.

Work in progress: tar is built; zip, extraction and 7z follow.

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
`testdata/` was written by the rivals' own tools (testdata/README.md).

## Licence

MIT.
