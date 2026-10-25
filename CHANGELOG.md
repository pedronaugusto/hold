# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- tar: `tar.Reader` reads v7, ustar, pax, GNU and sparse archives forward
  from any `std.Io.Reader`; `tar.Writer` writes ustar, pax and GNU.
- zip: `zip.Archive` reads through the central directory (ZIP64,
  prepended bytes, Info-ZIP's and NTFS's fields, overlapping entries
  refused), `zip.Stream` reads forward (data descriptors), `zip.Writer`
  writes (every field settable, store when larger, raw copy); WinZip AES
  read; stored, DEFLATE and zstd through warp.
- Interop: the tar archives of GNU tar, bsdtar, Python, Go, 7-Zip and
  libarchive's own test suite read to the entries and bytes libarchive
  reads; GNU tar, libarchive, Python, Go and 7-Zip read what hold writes.
  The zip archives of Info-ZIP, bsdtar, Python, Go, 7-Zip and libarchive's
  test suite read as libarchive reads them, each divergence named; UnZip,
  libarchive, Python, Go and 7-Zip read the zips hold writes.
- Extraction: `extract` writes any archive into a directory with the
  hostile-input rules on: names checked, no write through a link, links
  last and only inside, hard links only to files it wrote, specials
  refused or skipped, permissions as Python's `data` filter, a total
  bound. Files go through airlock, made durable 32 at a time in one
  batch at the level asked.
- 7z: `sevenz.Archive` reads encoded headers, solid folders of chained
  coders, empty streams and files, anti items, times and attributes and
  CRCs, and 7z AES with a password; copy, DEFLATE and zstd through warp.
  `extract` takes it. The archives 7-Zip writes with those coders read as
  libarchive reads them; the rest of libarchive's 7z corpus waits on
  warp's LZMA, each named in a `.hold` file.
- Benchmarks: `bench/main.zig` times tar, zip and 7z reading and writing
  over a source-shaped tree and two large files; `bench/rivals.sh` times
  libarchive and Go on the same rows over the same archives.

[Unreleased]: https://github.com/pedronaugusto/hold/commits/main
