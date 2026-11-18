# hold: design

Archive formats, both ways: tar and zip read and written, 7z read.

hold owns the containers: headers, directories, entry names, how an archive is laid out,
and the refusal of hostile input. It owns no codec: every compression method is **warp**'s.
Files reach a disk through **airlock**. Names are checked as text through **xenoglyph**
where the format calls them text. Units, limits and secrets are **aegis** types. None of
those packages depends on hold.

## Decisions

| Question | Decision | Why |
|---|---|---|
| Codecs | warp only, called by method. A method warp lacks is `error.UnsupportedMethod`, the method on the `Diagnostic`, and reads once warp has it. | One owner per job. Through warp hold reads stored, DEFLATE, Deflate64 (streamed), zstd, bzip2, LZMA and LZMA2 (raw, properties given apart: zip method 14 and 7z), xz, and xz's filters as readers of their own (7z's Delta and branch converters). |
| bzip2 | Read only. | warp decodes bzip2 and has no encoder. |
| Streaming | Every reader and writer works on `std.Io.Reader` and `std.Io.Writer`, one entry at a time; an entry's contents are a reader of exactly its size. Only a zip's central directory and a 7z header are held in memory, bounded by `Limits.directory`. | A forward tar or zip read works on a pipe. Holding the directory is what every rival does: metadata, not contents. |
| zip reading | Two readers: `zip.Archive` reads the central directory (a file or memory, random access); `zip.Stream` reads local headers forward, for pipes. `zip.Stream` refuses a stored entry with a data descriptor, and an encrypted one (`error.Unsupported`). | A stored entry's end with a descriptor cannot be found forward: scanning for the descriptor's signature is ambiguous, since it may occur in the data. |
| zip features | ZIP64 and data descriptors both ways; the UTF-8 flag (bit 11); Info-ZIP's Unicode path (0x7075, used when its CRC matches the header name); extended timestamps (0x5455); NTFS times (0x000a); Info-ZIP Unix uid and gid (0x7875); comments; an entry copied raw between archives. Bytes before the archive (a self-extractor's program) are skipped. | The set libarchive, Go and the Rust crate read. git, and so relic, writes 0x5455 and ZIP64. |
| zip encryption | WinZip AES read (AE-1 and AE-2; 128, 192 and 256 bits). Not written. ZipCrypto and PKWARE's strong encryption are `error.UnsupportedEncryption`. | AES is the only zip scheme with integrity (its HMAC). Writing it would ship the format's fixed PBKDF2-SHA1 at 1,000 iterations, too weak to offer as protection. ZipCrypto falls to a known-plaintext attack (Biham and Kocher, 1994): reading it protects nothing, writing it misleads. The password is an `aegis.SecretBytes`, erased once the keys are derived. |
| tar features | Read: v7, ustar, pax (local and global headers, `hdrcharset`, every standard keyword, `SCHILY.xattr.*`, `LIBARCHIVE.xattr.*`), GNU (long names `L`, long links `K`, base-256 numbers, old sparse `S`), sparse files as pax 0.0, 0.1 and 1.0. Write: ustar, pax (the default) and GNU, no sparse. | The read set is libarchive's and Go's. Sparse writing needs a filesystem scan, and hold has no filesystem source. |
| tar writer exactness | The caller sets every field the writer puts in a header: the pax header's own name, the ustar name left when the real name moves into pax, the checksum's spelling (`checksum`: GNU's, libarchive's and Go's `"%06o\0 "`, or git's `"%07o\0"`), the blocking factor (`blocking_factor`, 20 by default), uname and gname. | relic reproduces git's bytes exactly: git names its pax headers `<oid>.paxheader`, falls back to `<oid>.data`, and pads to 10,240-byte records. A writer deciding these alone would force relic to keep its own. |
| zip writer exactness | The caller sets the version made by (`made_by`) and needed, the internal and external attributes, raw extra fields (local and central), the DOS time, and when ZIP64 is used (`zip64`: `auto`, `always`, `never`). The writer computes what the format defines (sizes, CRC, offsets, ZIP64 records) and checks what the caller sets. `store_if_larger` stores an in-memory body that compressing would not shrink. | git writes version needed 10 for deflated entries, version made by 0 or 0x0317, its 0x5455 field, and a ZIP64 local field for a stream past 2 GiB. |
| 7z | Read only: the signature header, encoded headers, solid folders, several coders per folder and their bind pairs (a folder is the graph its binds make), empty streams and files, anti items, times and attributes, CRCs. Coders: copy, DEFLATE, Deflate64, zstd, LZMA, LZMA2, bzip2, Delta, the branch converters (x86, PowerPC, IA-64, ARM, ARM Thumb, SPARC, ARM64, RISC-V), BCJ2 (four streams into one), and 7z AES (SHA-256 key derivation, AES-256-CBC) with a password, its rounds bounded at 7-Zip's own 2^24. PPMd is `error.UnsupportedMethod`. Self-extracting 7z archives are not searched for. | No family user writes 7z. Without LZMA most real 7z files cannot be read (7-Zip and bsdtar encode the header with it). Entries of a solid folder share one decoder chain: read in order it decodes once, and an entry out of order decodes its folder again up to it, as libarchive does. The rounds' bound keeps a header from spending the caller's time on the key. |
| Names | Read as bytes, checked as text on request. A zip name is UTF-8 with bit 11 or a matching 0x7075 field, else code page 437 (APPNOTE 4.4.4), decoded through xenoglyph. A pax `path` is UTF-8 unless `hdrcharset=BINARY`. A 7z name is UTF-16LE. | One owner for text. |
| Extraction | `extract(io, gpa, dir, source, options)`, one path for every format (below). | Extraction is where every rival's CVEs live, so it is hold's to get right once. |
| Cancellation | `error.Canceled` checked once per entry and once per 1 MiB of contents copied. | The family's coarse-step rule. |
| Errors | One named set per call: `Invalid` for a malformed archive, `Truncated` for one that ends inside an entry, `Corrupt` for a CRC, size or MAC that disagrees, `LimitExceeded` past a limit. `Diagnostic` names the entry, the byte offset and the reason. | |

## Hostile input

The rules hold by default; turning one off takes an option whose name says it is unsafe.

1. **Names.** An entry is extracted only under a name that is relative, `/`-separated and
   normalized (`name.check`): empty and `.` components dropped; a `..` component, an absolute
   path, a drive letter, a UNC prefix, NUL and a backslash refused on every OS (a backslash
   is a separator on Windows, so `..\x` is a traversal there). Reading never rewrites a name:
   `Entry.name` is the archive's bytes, and the checked name is a separate call.
2. **Links.** Parent directories are opened a component at a time without following links;
   a link or a file where a directory belongs is `error.ThroughLink`, so no write passes
   through a symbolic link, the archive's or the destination's. A file is written to a temp
   beside its name and published by rename, so a name that was a link is replaced, never
   followed. With `links = .contained` (the default) a symbolic link is made only when its
   target stays inside the destination however it is followed (`name.checkLink`: `..` only as
   a prefix of the target, read from the link's directory); `.refuse` makes none, and
   `.any_unsafe` makes them as the archive says. A hard link must name a file this extraction
   wrote. Links are made after every file, so no later entry is written through one. Two
   names that fold together on a case-insensitive filesystem route no write anywhere new,
   since no write follows a link.
3. **Bombs.** Every byte written was declared first. A declared size is enforced exactly:
   the decoder is cut at it, and a mismatch is `Corrupt`. A zip whose entries' data overlap
   (Fifield's non-recursive bomb) is refused when it is opened: the local data ranges are
   sorted and must not overlap, and each local header must agree with its central record on
   the method and stay inside its range (the central name is the one used, as libarchive and
   Info-ZIP do). A zip entry streamed with an unknown size is bounded by `Limits.entry`.
   `Options.total` bounds what an extraction writes in all, and a zip's declared total is
   known when it is opened (`zip.Archive.declared`). hold opens no archive nested in another
   unless asked.
4. **Headers.** Every length an archive declares is checked against the bytes that remain
   before anything is allocated: a pax record, a GNU long name, a zip extra field, a central
   directory, a 7z header, and counts of entries, folders and coders. `Limits` holds each
   bound as an aegis unit: `header` 1 MiB per header record, `directory` 256 MiB, `entries`
   2^20, `window` (a decoder's) 128 MiB, `entry` unbounded unless the caller sets it.
5. **Specials.** Devices, FIFOs and entries of kind `other` are `error.Special`, or with
   `specials = .skip` passed over and counted; hold never makes one. Permissions follow
   Python's `data` filter (PEP 706, `mode = .data`): a file gets `(mode | 0o600) & 0o755`, a
   directory `(mode | 0o700) & 0o755`, so no set-user-ID, set-group-ID or sticky bit and no
   write for group or others; `mode = .exact_unsafe` keeps the archive's bits. Ownership is
   never changed. `times` sets each file's and directory's modification time to the archive's.
6. **Durability.** Each file is written to a temp and published by rename, made durable
   `batch_len` (32) at a time in one airlock `Batch` at the caller's `level` (`.none` by
   default, as every rival): a file sync each, one barrier, the renames in order, each
   directory touched once. Hard links follow once every file is published; links and
   directory times and permissions come last, in a final batch. A failure discards the open
   batch: nothing half-written is published. `place = .in_place`, for `level = .none` only,
   is the fast mode: each file created under its own name, exclusively (airlock's
   `Temp.in_place`, so a link there is never followed), with no temp and no rename, as
   libarchive writes, where a crash may leave a partial file under its name. The checks, the
   batch and the discard on failure are the same either way.
7. **Windows.** Reserved device names with any extension (`CON`, `NUL`, `COM1`...), a colon
   (an alternate data stream), and a trailing dot or space are refused there. Directory
   permissions are not set. Symbolic links are made through airlock (`target_kind`, read from
   the target, which extraction makes before its links), and hard links through airlock's
   `hardLink`, since std makes neither there.

## Edges

hold uses warp (codecs, CRC-32), airlock (extraction), xenoglyph (name text) and aegis
(units, secrets, the `Untrusted` boundary on every parser). Its tests and benchmarks use
shakedown, and its gate preflight. It is for the family's packages that read or write
archives; the writers' exactness options exist so relic's `git archive` output can be
written through it byte for byte.

## The bar

- **Correct:** every archive of libarchive's tar, zip and 7z test corpus inside hold's scope
  reads to the same entries and bytes as libarchive reads it; Info-ZIP, GNU tar, 7-Zip, Go
  and Python output is read; hold's output is read back by `bsdtar`, `gtar`, `unzip -t`,
  `7zz t` and Go.
- **Safe:** every parser has a fuzz target, and each hostile-input rule a test, the published
  CVE shapes among them (Zip Slip, an overlapping zip, a symbolic link then a write through
  it, a case-folded link, a pax path with `..`, a hard link out of the root).
- **Fast:** listing and extraction at least as fast as libarchive on the same files and
  machines, and tar and zip writing with DEFLATE at least as fast as Go and libarchive at the
  same warp level. Results are kept in trials (`results/hold/`). Publishing each file by
  rename costs extraction of many small files against libarchive's in-place writes, which
  `place = .in_place` answers; DEFLATE's own speed is warp's.

## Rivals

| Rival | What it does | Where hold stands |
|---|---|---|
| libarchive | The breadth leader in C: tar (every dialect), zip, 7z, cpio, ar, ISO 9660 and more; extraction guards (`ARCHIVE_EXTRACT_SECURE_*`) off by default in the library. | The rival on the same inputs, for formats and speed. Its guards are the model, and hold has them on by default. |
| Go `archive/zip`, `archive/tar` | Clean streaming APIs; zip through the central directory only, no encryption; insecure names an error only under `GODEBUG`. | API model (raw copy). hold refuses insecure names by default. |
| Rust `zip`, `tar` | zip both ways with AES and ZipCrypto both ways; tar both ways with path checks on unpack. | hold reads AES only. |
| Apache Commons Compress | Java: tar, zip, 7z both ways (AES, PPMd, filters), ar, cpio and more. | 7z reading scope. |
| Zig std `std.tar`, `std.zip` | tar read, a pax-lite writer and extract; zip read and extract only (stored and DEFLATE). | What a Zig user has without hold. |
| Info-ZIP, GNU tar, 7-Zip | The reference tools. | Interop: their output is read, and hold's passes theirs. |

Encryption, history and every rival's version are in each rival's own documentation; the
interop tests (`src/testing/interop_test.zig`) name the tools they run.
