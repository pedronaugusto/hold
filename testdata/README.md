# The interop corpus

Archives the rivals' own tools wrote, read by `src/testing/interop_test.zig`.
Each `<archive>.manifest` is what libarchive 3.8.9 reads from it, written by
a small C program over libarchive: a line per entry, `<kind> <size> <mode> <mtime> <FNV-1a 64
of the contents> <name>\t<link>`. hold must read the same lines. Where hold
reads an archive otherwise on purpose, `<archive>.hold` holds hold's lines and,
in its `# ` lines, why.

- `tar/`: one tree archived by GNU tar 1.35 (`gtar-*`, every `--format`),
  bsdtar 3.7.4 (`bsdtar-*`), Python 3.13 `tarfile` (`python-*`), Go 1.27.1
  `archive/tar` (`go-pax.tar`) and 7-Zip 26.04 (`7zz.tar`). Written on
  macOS, 2026-10-25.
- `libarchive/`: the tar archives of libarchive 3.8.1's own test suite
  (`libarchive/test/*.uu`, decoded): GNU tar 1.13 and 1.17 sparse files in
  every GNU and pax version, Solaris and star ACLs, Mac metadata, empty and
  concatenated archives, archives libarchive refuses. The 8 MB
  `tar_pax_large_attr` is left out.

- `zip/`: one tree zipped by Info-ZIP Zip 3.0 (`infozip-*`: DEFLATE, stored,
  forced ZIP64, standard input with a data descriptor), bsdtar 3.7.4 and
  3.8.9 (`bsdtar38-*`: zstd, bzip2, LZMA, xz), Python 3.13 `zipfile`, Go
  1.27.1 `archive/zip` (data descriptors, a comment) and 7-Zip 26.04
  (DEFLATE, Deflate64, bzip2, AES-128, AES-192, AES-256, ZipCrypto; password
  `hold`). Manifests read with `TZ=UTC`.
- `libarchive/zip*`: the zip archives of libarchive 3.8.1's test suite
  (passwords `password` and `12345678`).

- `sevenz/`: the zip tree by 7-Zip 26.05 (`7zz-*`, headers left plain:
  copy, DEFLATE solid and not, times, Deflate64, bzip2, LZMA2, x86 BCJ, AES
  with password `hold` on copy and DEFLATE and on the header) and bsdtar
  3.8 (`bsdtar38-*`, every 7z compression it writes); `7zz-bcj2.7z` is
  libarchive's x86 test program (`7zip_bcj2_copy_1.7z`) by 7-Zip 26.05 with
  `-mf=BCJ2` (BCJ2 over LZMA2 and LZMA, its header encoded).
- `libarchive/7zip_*`: the 7z archives of libarchive 3.8.1's test suite;
  its three self-extractors are left out (hold reads no self-extractor).

Names are compared in NFC: libarchive's macOS build hands names out in NFD.
A `.hold` file's reasons name each divergence: a time read from another field,
a method refused by name, an encryption libarchive does not read.

`testdata.zig` indexes the corpus for the tests: `bay testdata-index`
(`tools/index.zig`) writes it again after an archive or a `.hold` file comes
or goes.

The other direction is checked outside this repository: `bay interop-write`
(`tools/write.zig`) writes the same entries as ustar, pax and GNU, and zips
(DEFLATE, stored, zstd, streamed with descriptors, forced ZIP64); libarchive
must read the manifest hold wrote, and GNU tar, Python, Go, UnZip and 7-Zip
must read them.
