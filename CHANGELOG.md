# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Breaking

- `Entry.Encoding` has no `cp437`: a zip name an MS-DOS host wrote in code
  page 437 comes decoded to UTF-8 (through xenoglyph), as libarchive gives
  it; `zip.Record.raw_name` keeps the bytes and `zip.Record.cp437` says the
  name was decoded. A name without the UTF-8 flag that is well-formed UTF-8
  is UTF-8, and another host's name that is not is `.unspecified` bytes.
- `zip.Record.made_by` is null for a record read forward, where a local
  header names no host.

### Added

- 7z coders LZMA (030101), LZMA2 (21), bzip2 (040202), Delta (03) and the
  branch converters for x86, PowerPC, IA-64, ARM, ARM Thumb, SPARC, ARM64
  and RISC-V, through warp's LZMA, bzip2 and xz filter readers: 7-Zip's
  and bsdtar's archives, whose headers are LZMA, now read as libarchive
  reads them. An LZMA window is no larger than the contents it decodes.
- zip methods 12 (bzip2) and 14 (LZMA, its properties leading the stream).

### Changed

- Pins aegis 0.2.3, the 0.2 line, airlock 0.6.0 and xenoglyph 0.5.1, and
  warp at its 0.5.0 car until the tag; developed with shakedown 0.6.0 and
  preflight 0.18.5.
- AES keys, key schedules, MAC states and keystreams are held in aegis
  `Secret`s and compared through `aegis.secret.equal`; 7z AES no longer
  wipes the staged plaintext, which is the caller's to read, as zip AES's
  never was.
- Times convert through aegis instants in one place (Unix seconds, pax
  seconds and nanoseconds, FILETIME); a pax time past an i64's seconds is
  `error.InvalidTime`.
- A tar entry's pax records, GNU long name and link are each read into an
  allocation of their own, released at the next entry.
- A zstd stream is decoded frame by frame, each over the window its own
  header names: 7-Zip's zstd folders start with an empty frame of a small
  window, and their data frame's larger one was refused.
- A malformed pax sparse map (GNU 0.0) and a zip whose extra fields break
  are refused where they are read, with the diagnostic's `sparse_map` or
  `extra_field`; the fields a local header holds are found in the one pass
  that checks them.

### Fixed

- `tar.Writer` writes a pax time of the most negative nanoseconds an
  `Io.Timestamp` holds, where taking its magnitude stopped a safe build.

## [0.1.1] - 2026-10-25

### Added

- Deflate64: zip entries of method 9 and 7z folders with coder 040109 read
  through warp's streaming Deflate64 decoder (64 KiB window, within
  `Limits.window`). 7-Zip's Deflate64 zip reads as libarchive reads it;
  its Deflate64 7z, which libarchive 3.8.9 cannot read, is read in full.

### Changed

- Pins warp 0.4.4, for its Deflate64 decoder.
- Development: the rival programs and the scripts that drove the rivals'
  tools (`bench/rivals.sh` and `bench/rivals/`, `testdata/make.sh`,
  `testdata/interop.sh`, `testdata/git/make.sh`, `testdata/tools/manifest.c`)
  moved to the private trials repository (`hold/`), the drivers rewritten in
  Zig; the archives they wrote stay committed here. `testdata/index.sh` is
  `testdata/tools/index.zig` (`bay testdata-index`).

## [0.1.0] - 2026-10-25

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
