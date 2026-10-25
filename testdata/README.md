# The interop corpus

Archives the rivals' own tools wrote, read by `src/testing/interop_test.zig`.
Each `<archive>.manifest` is what libarchive 3.8.10 reads from it, written by
`tools/manifest.c`: a line per entry, `<kind> <size> <mode> <mtime> <FNV-1a 64
of the contents> <name>\t<link>`. hold must read the same lines. Where hold
reads an archive otherwise on purpose, `<archive>.hold` holds hold's lines and,
in its `# ` lines, why.

- `tar/`: one tree archived by GNU tar 1.35 (`gtar-*`, every `--format`),
  bsdtar 3.7.4 (`bsdtar-*`), Python 3.13 `tarfile` (`python-*`), Go 1.27.1
  `archive/tar` (`go-pax.tar`) and 7-Zip 26.04 (`7zz.tar`). Written by
  `make.sh` on macOS, 2026-10-25.
- `libarchive/`: the tar archives of libarchive 3.8.1's own test suite
  (`libarchive/test/*.uu`, decoded): GNU tar 1.13 and 1.17 sparse files in
  every GNU and pax version, Solaris and star ACLs, Mac metadata, empty and
  concatenated archives, archives libarchive refuses. The 8 MB
  `tar_pax_large_attr` is left out.

- `zip/`: one tree zipped by Info-ZIP Zip 3.0 (`infozip-*`: DEFLATE, stored,
  forced ZIP64, standard input with a data descriptor), bsdtar 3.7.4 and
  3.8.10 (`bsdtar38-*`: zstd, bzip2, LZMA, xz), Python 3.13 `zipfile`, Go
  1.27.1 `archive/zip` (data descriptors, a comment) and 7-Zip 26.04
  (DEFLATE, Deflate64, bzip2, AES-128, AES-192, AES-256, ZipCrypto; password
  `hold`). Manifests read with `TZ=UTC`.
- `libarchive/zip*`: the zip archives of libarchive 3.8.1's test suite
  (passwords `password` and `12345678`).

Names are compared in NFC: libarchive's macOS build hands names out in NFD.
A `.hold` file's reasons name each divergence; most are methods warp has no
decoder for yet, and become libarchive's lines when warp has them.

`interop.sh` checks the other direction: `bay interop-write` writes the same
entries as ustar, pax and GNU, libarchive must read the manifest hold wrote,
and GNU tar, Python, Go and 7-Zip must list and extract them; it writes zips
(DEFLATE, stored, zstd, streamed with descriptors, forced ZIP64) that
libarchive, UnZip, Python, Go and 7-Zip must read.
