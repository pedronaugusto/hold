# hold: design

hold owns archive containers: headers, directories, entry names, layout and
the refusal of hostile input. It owns no codec: every compression method is
warp's. Files reach a disk through airlock.

## Readers and writers

Every reader works on a `std.Io.Reader` and hands out one entry at a time;
its contents are a `std.Io.Reader` of exactly the entry's size. Every writer
works on a `std.Io.Writer`; an entry is a header, then exactly its size in
contents. Nothing buffers a whole archive or a whole entry.

## Hostile input

Every length an archive declares is checked against `Limits` before anything
is allocated for it. A malformed header is `error.Invalid`, an archive that
ends inside an entry `error.Truncated`, and a length past a limit
`error.LimitExceeded`, each with a `Diagnostic` naming the entry, the offset
and the reason.

## Extraction

`extract` checks every name (`name.check`), opens parents a component at a
time without following links, writes each file to a temp beside its name
and publishes it by rename, and makes links last, only where they stay
inside. Files are made durable `batch_len` at a time in one airlock batch.
At `level = .none` a caller may ask for files in place (`Place.in_place`,
airlock's exclusive create under the name: no temp, no rename): the fast
mode, as libarchive writes, where a crash may leave a partial file under its
name. One path: the batch, the checks and the discard on failure are the
same; only where the bytes land differs.
The full rules, with the rivals' and the reasons, are on the design page
in tychobook.
