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

`interop.sh` checks the other direction: `bay interop-write` writes the same
entries as ustar, pax and GNU, libarchive must read the manifest hold wrote,
and GNU tar, Python, Go and 7-Zip must list and extract them.
