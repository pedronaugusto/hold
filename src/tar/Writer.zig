//! Writes a tar archive to any `std.Io.Writer`: ustar, pax (the default)
//! or GNU. An entry is a header, then exactly its size in contents through
//! `contents()`; `add` does both for contents in memory. What a dialect
//! cannot hold goes where that dialect puts it: pax records, GNU long
//! names and base-256 numbers. ustar refuses it.
//!
//! Every field the writer puts in a header can be set (`Header`), so a
//! caller can reproduce another writer's bytes exactly: git's pax header
//! names, its `.data` fallback, its checksum spelling and its blocking.
const Writer = @This();

const std = @import("std");
const Io = std.Io;
const header = @import("header.zig");
const pax = @import("pax.zig");
const Entry = @import("../Entry.zig");

pub const Format = enum { ustar, pax, gnu };

pub const Options = struct {
    format: Format = .pax,
    checksum: header.ChecksumStyle = .nul_space,
    /// Records per block: the archive ends padded to a multiple of 512 ×
    /// this, as POSIX's default of 20 (10,240 bytes) pads it.
    blocking_factor: u16 = 20,
    /// The longest prefix a ustar name splits off: 155 by the format, 154
    /// as git splits.
    ustar_prefix: u8 = header.prefix.len,
};

/// An entry, and how its header is spelled where the dialect leaves a
/// choice.
pub const Header = struct {
    entry: Entry,
    /// The name of the pax header that carries what the entry's own header
    /// cannot: by default `<dir>/PaxHeaders/<base>`, as GNU tar names it.
    pax_name: ?[]const u8 = null,
    /// The pax header's mode.
    pax_mode: u32 = 0o644,
    /// The name the entry's header carries when its real name moves into a
    /// pax record: by default the name's first 100 bytes.
    ustar_name: ?[]const u8 = null,
    /// The link the entry's header carries when its real link moves into a
    /// pax record: by default the link's first 100 bytes.
    ustar_link: ?[]const u8 = null,
    /// More pax records for the entry (`SCHILY.xattr.*`, `comment`), after
    /// the ones the writer makes.
    records: []const pax.Record = &.{},
    /// pax only: put the times in records whenever they have a fraction of
    /// a second, not only when the header cannot hold their seconds.
    exact_times: bool = false,
};

/// Private: the archive.
output: *Io.Writer,
options: Options,
/// Private: bytes written to the archive.
written: u64 = 0,
/// Private: contents still owed by the current entry, and its padding.
left: u64 = 0,
pad: u64 = 0,
/// Private: an entry is open.
open: bool = false,
finished: bool = false,
/// Private: the contents' writer.
interface: Io.Writer,
/// Private: why the contents' writer failed, when it was the entry.
failure: ?ContentsError = null,

pub const ContentsError = error{
    /// More contents than the entry's size.
    TooLong,
};

pub const BeginError = error{
    /// The entry's previous one still owes contents.
    EntryOpen,
    /// The dialect cannot hold a field (ustar), or a field is out of every
    /// dialect's range: a name or link with a NUL, a device number past
    /// what a header holds, an `other` entry.
    Unrepresentable,
    WriteFailed,
};

pub const EndError = error{
    /// Fewer contents than the entry's size.
    TooShort,
    WriteFailed,
};

pub const FinishError = EndError || error{EntryOpen};

/// `buffer` stages the contents; any length works.
pub fn init(output: *Io.Writer, buffer: []u8, options: Options) Writer {
    std.debug.assert(options.blocking_factor != 0);
    return .{ .output = output, .options = options, .interface = .{ .vtable = &vtable, .buffer = buffer } };
}

/// Writes the entry's header (and any pax or GNU headers before it); the
/// contents follow through `contents()`, exactly `entry.size` bytes of
/// them for a file or a hard link that carries data.
pub fn begin(w: *Writer, h: Header) BeginError!void {
    if (w.open) return error.EntryOpen;
    std.debug.assert(!w.finished);
    const e = h.entry;
    if (e.kind == .other) return error.Unrepresentable;
    if (std.mem.findScalar(u8, e.name, 0) != null or std.mem.findScalar(u8, e.link, 0) != null) return error.Unrepresentable;
    const size: u64 = switch (e.kind) {
        .file, .hardlink => e.size,
        else => 0,
    };
    var d: Draft = .{ .format = w.options.format };
    try w.draftNames(&d, h);
    try d.numbers(e, size);
    try d.times(h);
    try d.owners(e);
    d.b[header.typeflag] = switch (e.kind) {
        .file => '0',
        .hardlink => '1',
        .symlink => '2',
        .character_device => '3',
        .block_device => '4',
        .directory => '5',
        .fifo => '6',
        .other => unreachable, // unreachable: refused above
    };
    if (d.format == .gnu) {
        @memcpy(d.b[257..265], "ustar  \x00");
    } else {
        @memcpy(d.b[257..263], "ustar\x00");
        @memcpy(d.b[263..265], "00");
    }
    if (d.n != 0 or h.records.len != 0) {
        if (d.format != .pax) return error.Unrepresentable;
        try w.paxHeader('x', d.records[0..d.n], h.records, h);
    }
    header.putChecksum(&d.b, w.options.checksum);
    try w.raw(&d.b);
    w.left = size;
    w.pad = padding(size);
    w.open = true;
}

/// An entry's header as it is made, and the pax records it needs.
const Draft = struct {
    format: Format,
    b: header.Block = std.mem.zeroes(header.Block),
    records: [12]pax.Record = undefined,
    n: usize = 0,
    /// Room for the records' values the draft formats itself.
    digits: [3][24]u8 = undefined,
    stamps: [3][40]u8 = undefined,

    fn record(d: *Draft, key: []const u8, value: []const u8) void {
        d.records[d.n] = .{ .key = key, .value = value };
        d.n += 1;
    }

    /// uid, gid and size: octal where they fit, else a pax record (the
    /// field zero) or base-256 (GNU).
    fn numbers(d: *Draft, e: Entry, size: u64) BeginError!void {
        const Number = struct { field: header.Field, key: []const u8, value: u64 };
        const nums = [_]Number{
            .{ .field = header.uid, .key = "uid", .value = e.uid orelse 0 },
            .{ .field = header.gid, .key = "gid", .value = e.gid orelse 0 },
            .{ .field = header.size, .key = "size", .value = size },
        };
        for (nums, 0..) |num, i| {
            if (header.fitsOctal(num.field.len, num.value)) {
                header.putOctal(num.field.slot(&d.b), num.value);
            } else switch (d.format) {
                .ustar => return error.Unrepresentable,
                .pax => {
                    d.record(num.key, d.digits[i][0..std.fmt.printInt(&d.digits[i], num.value, 10, .lower, .{})]);
                    header.putOctal(num.field.slot(&d.b), 0);
                },
                .gnu => header.putBase256(num.field.slot(&d.b), std.math.cast(i64, num.value) orelse return error.Unrepresentable),
            }
        }
        header.putOctal(header.mode.slot(&d.b), (e.mode orelse defaultMode(e.kind)) & 0o7777);
        const major = e.device.major;
        const minor = e.device.minor;
        if (header.fitsOctal(8, major) and header.fitsOctal(8, minor)) {
            header.putOctal(header.devmajor.slot(&d.b), major);
            header.putOctal(header.devminor.slot(&d.b), minor);
        } else {
            if (d.format != .gnu) return error.Unrepresentable;
            header.putBase256(header.devmajor.slot(&d.b), major);
            header.putBase256(header.devminor.slot(&d.b), minor);
        }
    }

    /// The modification time in the header where its seconds fit, and in
    /// a record (pax) or base-256 (GNU) where they do not; pax's atime and
    /// ctime as records, GNU's in its own fields.
    fn times(d: *Draft, h: Header) BeginError!void {
        const e = h.entry;
        const mtime = e.mtime orelse Entry.seconds(0);
        const secs = @divFloor(mtime.nanoseconds, std.time.ns_per_s);
        const whole = @rem(mtime.nanoseconds, std.time.ns_per_s) == 0;
        const fits = secs >= 0 and header.fitsOctal(12, @intCast(@min(secs, std.math.maxInt(u64))));
        if (fits) {
            header.putOctal(header.mtime.slot(&d.b), @intCast(secs));
        } else switch (d.format) {
            .ustar => return error.Unrepresentable,
            .pax => header.putOctal(header.mtime.slot(&d.b), if (secs < 0) 0 else 0o77777777777),
            .gnu => header.putBase256(header.mtime.slot(&d.b), std.math.cast(i64, secs) orelse return error.Unrepresentable),
        }
        switch (d.format) {
            .pax => {
                if (!fits or (h.exact_times and !whole)) d.record("mtime", pax.formatTime(mtime, &d.stamps[0]));
                if (e.atime) |t| d.record("atime", pax.formatTime(t, &d.stamps[1]));
                if (e.ctime) |t| d.record("ctime", pax.formatTime(t, &d.stamps[2]));
            },
            .gnu => {
                if (e.atime) |t| header.putTime(header.gnu_atime.slot(&d.b), t);
                if (e.ctime) |t| header.putTime(header.gnu_ctime.slot(&d.b), t);
            },
            .ustar => {},
        }
    }

    /// uname and gname, in records when they do not fit or are not ASCII.
    fn owners(d: *Draft, e: Entry) BeginError!void {
        inline for (.{ .{ header.uname, "uname", e.uname }, .{ header.gname, "gname", e.gname } }) |o| {
            if (o[2].len <= o[0].len and (d.format != .pax or isAscii(o[2]))) {
                @memcpy(d.b[o[0].start..][0..o[2].len], o[2]);
            } else switch (d.format) {
                .pax => {
                    d.record(o[1], o[2]);
                    putTruncated(o[0].slot(&d.b), o[2]);
                },
                else => return error.Unrepresentable,
            }
        }
    }
};

/// The name and link: in the header where they fit (a ustar name split at
/// a `/`), else in records (pax) or GNU long headers written now, before
/// the entry's.
fn draftNames(w: *Writer, d: *Draft, h: Header) BeginError!void {
    const e = h.entry;
    const name_text = d.format != .pax or isAscii(e.name);
    const split = if (e.name.len <= header.name.len) null else splitPrefix(e.name, w.options.ustar_prefix);
    if (e.name.len <= header.name.len and name_text) {
        @memcpy(d.b[0..e.name.len], e.name);
    } else if (split != null and name_text and d.format != .gnu) {
        const i = split.?;
        @memcpy(header.prefix.slot(&d.b)[0..i], e.name[0..i]);
        @memcpy(header.name.slot(&d.b)[0 .. e.name.len - i - 1], e.name[i + 1 ..]);
    } else switch (d.format) {
        .ustar => return error.Unrepresentable,
        .pax => {
            d.record("path", e.name);
            putTruncated(header.name.slot(&d.b), h.ustar_name orelse e.name);
        },
        .gnu => {
            try w.longHeader('L', e.name, h);
            putTruncated(header.name.slot(&d.b), h.ustar_name orelse e.name);
        },
    }
    if (e.link.len <= header.linkname.len and (d.format != .pax or isAscii(e.link))) {
        @memcpy(d.b[header.linkname.start..][0..e.link.len], e.link);
    } else switch (d.format) {
        .ustar => return error.Unrepresentable,
        .pax => {
            d.record("linkpath", e.link);
            putTruncated(header.linkname.slot(&d.b), h.ustar_link orelse e.link);
        },
        .gnu => {
            try w.longHeader('K', e.link, h);
            putTruncated(header.linkname.slot(&d.b), h.ustar_link orelse e.link);
        },
    }
}

/// Ends the current entry: its contents must all have been written.
pub fn end(w: *Writer) EndError!void {
    std.debug.assert(w.open);
    try w.drainStaged();
    if (w.left != 0) return error.TooShort;
    try w.zeros(w.pad);
    w.pad = 0;
    w.open = false;
}

/// An entry whose contents are in memory: `begin`, the bytes, `end`.
pub fn add(w: *Writer, h: Header, bytes: []const u8) (BeginError || EndError || ContentsError)!void {
    var with_size = h;
    if (h.entry.kind == .file or h.entry.kind == .hardlink) with_size.entry.size = bytes.len;
    try w.begin(with_size);
    w.interface.writeAll(bytes) catch return w.failure orelse error.WriteFailed;
    try w.end();
}

/// The current entry's contents.
pub fn contents(w: *Writer) *Io.Writer {
    std.debug.assert(w.open);
    return &w.interface;
}

/// A pax global header: records every later entry takes. `h.entry` gives
/// the header's own fields (git's `pax_global_header`, for one).
pub fn global(w: *Writer, h: Header) BeginError!void {
    if (w.open) return error.EntryOpen;
    if (w.options.format != .pax) return error.Unrepresentable;
    var b = std.mem.zeroes(header.Block);
    try w.paxBlock(&b, 'g', h.entry.name, h.pax_mode, h);
    var len: u64 = 0;
    for (h.records) |rec| len += pax.recordLen(rec.key, rec.value);
    header.putOctal(header.size.slot(&b), len);
    header.putChecksum(&b, w.options.checksum);
    try w.raw(&b);
    for (h.records) |rec| try w.record(rec.key, rec.value);
    try w.zeros(padding(len));
}

/// Ends the archive: two zero blocks, padded to the blocking factor.
pub fn finish(w: *Writer) FinishError!void {
    if (w.open) return error.EntryOpen;
    std.debug.assert(!w.finished);
    try w.zeros(2 * header.block_len);
    const record_len = @as(u64, w.options.blocking_factor) * header.block_len;
    try w.zeros((record_len - w.written % record_len) % record_len);
    w.output.flush() catch return error.WriteFailed;
    w.finished = true;
}

//=========================================================================

fn defaultMode(kind: Entry.Kind) u32 {
    return switch (kind) {
        .directory => 0o755,
        .symlink => 0o777,
        else => 0o644,
    };
}

fn isAscii(s: []const u8) bool {
    for (s) |c| if (c >= 0x80) return false;
    return true;
}

fn putTruncated(field: []u8, s: []const u8) void {
    const n = @min(field.len, s.len);
    @memcpy(field[0..n], s[0..n]);
}

fn splitPrefix(path: []const u8, max: u8) ?usize {
    const i = header.splitUstar(path) orelse return null;
    if (i <= max) return i;
    // A shorter prefix leaves a longer name: find the last `/` at or
    // before the limit.
    var j: usize = max;
    while (j > 0) : (j -= 1) {
        if (path[j] == '/' and path.len - j - 1 <= header.name.len and path.len - j - 1 > 0) return j;
    }
    return null;
}

fn padding(size: u64) u64 {
    return (header.block_len - size % header.block_len) % header.block_len;
}

fn raw(w: *Writer, bytes: []const u8) error{WriteFailed}!void {
    try w.output.writeAll(bytes);
    w.written += bytes.len;
}

fn zeros(w: *Writer, n: u64) error{WriteFailed}!void {
    try w.output.splatByteAll(0, @intCast(n));
    w.written += n;
}

fn record(w: *Writer, key: []const u8, value: []const u8) error{WriteFailed}!void {
    try pax.write(w.output, key, value);
    w.written += pax.recordLen(key, value);
}

/// The fields a pax or GNU long header shares with its entry's.
fn paxBlock(w: *Writer, b: *header.Block, flag: u8, name: []const u8, mode: u32, h: Header) BeginError!void {
    _ = w;
    putTruncated(header.name.slot(b), name);
    header.putOctal(header.mode.slot(b), mode & 0o7777);
    const e = h.entry;
    header.putOctal(header.uid.slot(b), if (e.uid) |v| (if (header.fitsOctal(8, v)) v else 0) else 0);
    header.putOctal(header.gid.slot(b), if (e.gid) |v| (if (header.fitsOctal(8, v)) v else 0) else 0);
    const secs: i96 = if (e.mtime) |t| @divFloor(t.nanoseconds, std.time.ns_per_s) else 0;
    header.putOctal(header.mtime.slot(b), @intCast(std.math.clamp(secs, 0, 0o77777777777)));
    header.putOctal(header.devmajor.slot(b), 0);
    header.putOctal(header.devminor.slot(b), 0);
    if (e.uname.len <= header.uname.len) @memcpy(b[header.uname.start..][0..e.uname.len], e.uname);
    if (e.gname.len <= header.gname.len) @memcpy(b[header.gname.start..][0..e.gname.len], e.gname);
    b[header.typeflag] = flag;
    @memcpy(b[257..263], "ustar\x00");
    @memcpy(b[263..265], "00");
}

/// A pax header with the writer's records and the caller's, before the
/// entry whose header is `entry_block`.
fn paxHeader(w: *Writer, flag: u8, made: []const pax.Record, extra: []const pax.Record, h: Header) BeginError!void {
    var b = std.mem.zeroes(header.Block);
    var default_name: [header.name.len]u8 = undefined;
    const name = h.pax_name orelse defaultPaxName(h.entry.name, &default_name);
    try w.paxBlock(&b, flag, name, h.pax_mode, h);
    var len: u64 = 0;
    for (made) |rec| len += pax.recordLen(rec.key, rec.value);
    for (extra) |rec| len += pax.recordLen(rec.key, rec.value);
    header.putOctal(header.size.slot(&b), len);
    header.putChecksum(&b, w.options.checksum);
    try w.raw(&b);
    for (made) |rec| try w.record(rec.key, rec.value);
    for (extra) |rec| try w.record(rec.key, rec.value);
    try w.zeros(padding(len));
}

/// `<dir>/PaxHeaders/<base>`, the first 100 bytes of it.
fn defaultPaxName(name: []const u8, buffer: *[header.name.len]u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, name, "/");
    const slash = std.mem.findScalarLast(u8, trimmed, '/');
    const dir = if (slash) |i| trimmed[0 .. i + 1] else "";
    const base = if (slash) |i| trimmed[i + 1 ..] else trimmed;
    // The name is the first 100 bytes of the three pieces.
    var at: usize = 0;
    for ([_][]const u8{ dir, "PaxHeaders/", base }) |piece| {
        const n = @min(piece.len, buffer.len - at);
        @memcpy(buffer[at..][0..n], piece[0..n]);
        at += n;
    }
    return buffer[0..at];
}

/// GNU's `././@LongLink` header and the name or link it carries.
fn longHeader(w: *Writer, flag: u8, text: []const u8, h: Header) BeginError!void {
    var b = std.mem.zeroes(header.Block);
    try w.paxBlock(&b, flag, "././@LongLink", 0o644, h);
    @memcpy(b[257..265], "ustar  \x00");
    const len = text.len + 1;
    if (!header.fitsOctal(12, len)) return error.Unrepresentable;
    header.putOctal(header.size.slot(&b), len);
    header.putChecksum(&b, w.options.checksum);
    try w.raw(&b);
    try w.raw(text);
    try w.zeros(1 + padding(len));
}

//=========================================================================
// Contents

const vtable: Io.Writer.VTable = .{ .drain = drain };

fn drainStaged(w: *Writer) error{WriteFailed}!void {
    const staged = w.interface.buffered();
    if (staged.len == 0) return;
    if (staged.len > w.left) {
        w.failure = error.TooLong;
        return error.WriteFailed;
    }
    try w.raw(staged);
    w.left -= staged.len;
    w.interface.end = 0;
}

fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const w: *Writer = @fieldParentPtr("interface", io_w);
    try w.drainStaged();
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        if (bytes.len > w.left) {
            w.failure = error.TooLong;
            return error.WriteFailed;
        }
        try w.raw(bytes);
        w.left -= bytes.len;
        n += bytes.len;
    }
    const last = data[data.len - 1];
    if (@as(u128, last.len) * splat > w.left) {
        w.failure = error.TooLong;
        return error.WriteFailed;
    }
    for (0..splat) |_| try w.raw(last);
    w.left -= last.len * splat;
    return n + last.len * splat;
}
