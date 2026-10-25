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
