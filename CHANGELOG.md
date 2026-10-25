# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- tar: `tar.Reader` reads v7, ustar, pax, GNU and sparse archives forward
  from any `std.Io.Reader`; `tar.Writer` writes ustar, pax and GNU.
- Interop: the tar archives of GNU tar, bsdtar, Python, Go, 7-Zip and
  libarchive's own test suite read to the entries and bytes libarchive
  reads; GNU tar, libarchive, Python, Go and 7-Zip read what hold writes.

[Unreleased]: https://github.com/pedronaugusto/hold/commits/main
