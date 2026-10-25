//! Reads a tar archive forward from any `std.Io.Reader`, one entry at a
//! time: v7, ustar, pax (local and global headers) and GNU (long names and
//! links, base-256 numbers, old sparse files), and sparse files as pax
//! 0.0, 0.1 and 1.0 describe them. An entry's contents are read through
//! `contents()`, holes of a sparse file as zeros; `next` passes over what
//! the caller left unread.
//!
//! Every length a header declares is checked against `Limits` before it
//! is read; a header that is no header is `error.Invalid`, and an archive
//! that ends inside an entry `error.Truncated`.
const Reader = @This();

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const header = @import("header.zig");
const pax = @import("pax.zig");
const Entry = @import("../Entry.zig");
const Limits = @import("../Limits.zig");
const Diagnostic = @import("../Diagnostic.zig");

pub const Options = struct {
    limits: Limits = .{},
    diagnostic: ?*Diagnostic = null,
};

/// A run of a sparse file's data: `len` bytes stored for the file's bytes
/// from `offset`; the bytes between runs are zeros.
pub const Segment = struct { offset: u64, len: u64 };

/// How the current entry was written.
pub const Format = enum { v7, ustar, pax, gnu };

/// Private: the allocator of the header buffers.
gpa: Allocator,
/// Private: the archive.
input: *Io.Reader,
options: Options,
/// Private: the archive's offset at the input's position.
offset: u64 = 0,
/// Private: entries returned so far.
entries: u64 = 0,
/// Private: the trailer was read.
done: bool = false,
/// Private: the current entry's header, which its fields borrow.
block: header.Block = undefined,
/// Private: a ustar name joined from its prefix and name.
joined: [header.prefix.len + 1 + header.name.len]u8 = undefined,
/// Private: the current entry's pax records, GNU long name and link.
local: std.ArrayList(u8) = .empty,
long_name: std.ArrayList(u8) = .empty,
long_link: std.ArrayList(u8) = .empty,
/// Private: the pax records every later entry takes, re-encoded.
global: std.ArrayList(u8) = .empty,
/// Private: the current entry's sparse map, empty for a plain file.
sparse: std.ArrayList(Segment) = .empty,
/// Private: the current entry's typeflag and format.
flag: u8 = 0,
format: Format = .ustar,
/// Private: a pax header was read, so a hard link's size is its data's
/// (POSIX.1-2001); before pax, writers put a size on hard links with no
/// data after them, and readers ignore it.
pax_seen: bool = false,
/// Private: the bytes of a pax 1.0 sparse map read at the data's start.
map_used: u64 = 0,
/// Private: the contents' reader and where it is.
reader: Contents,

pub const NextError = error{
    /// A header, a number in one or a pax record is malformed, or a
    /// checksum disagrees.
    Invalid,
    /// The archive ended inside a header or an entry's data.
    Truncated,
    /// A length or count past `Options.limits`.
    LimitExceeded,
    /// The archive's input failed: its own error says why.
    ReadFailed,
    OutOfMemory,
};

/// `buffer` holds the contents' reads; any length, zero included, works
/// with `stream`-based reads (`streamRemaining`, `discard`), and the
/// buffered reads (`peek`, `take`) need it as long as what they ask.
pub fn init(gpa: Allocator, input: *Io.Reader, buffer: []u8, options: Options) Reader {
    return .{
        .gpa = gpa,
        .input = input,
        .options = options,
        .reader = .{ .interface = .{ .vtable = &Contents.vtable, .buffer = buffer, .seek = 0, .end = 0 } },
    };
}

pub fn deinit(r: *Reader) void {
    r.local.deinit(r.gpa);
    r.long_name.deinit(r.gpa);
    r.long_link.deinit(r.gpa);
    r.global.deinit(r.gpa);
    r.sparse.deinit(r.gpa);
    r.* = undefined;
}

/// The next entry, or null after the archive's end. Its slices borrow from
/// the reader until the next call.
pub fn next(r: *Reader) NextError!?Entry {
    if (r.done) return null;
    try r.skipRest();
    r.local.clearRetainingCapacity();
    r.long_name.clearRetainingCapacity();
    r.long_link.clearRetainingCapacity();
    r.sparse.clearRetainingCapacity();
    var saw_extension = false;
    while (true) {
        const at = r.offset;
        if (!try r.readBlock(&r.block, saw_extension)) {
            r.done = true;
            return null;
        }
        if (header.isZero(&r.block)) {
            // The trailer is two zero blocks, but the first ends the
            // archive: what follows it is padding, often a tape's old
            // bytes, and libarchive reads no further either. An extended
            // header with no entry after it describes nothing.
            r.done = true;
            return null;
        }
        if (!header.checksumValid(&r.block)) return r.fail(at, .checksum, error.Invalid);
        const flag = r.block[header.typeflag];
        const size = header.unsigned(header.size.of(&r.block)) catch return r.fail(at, .header_field, error.Invalid);
        switch (flag) {
            'A' => {
                // A Solaris ACL for the next entry: ACLs are not read, so
                // its data is passed over as the extension it is.
                try r.skipData(size, at);
                saw_extension = true;
            },
            'x', 'X' => {
                try r.readData(&r.local, size, at);
                try r.checkRecords(r.local.items, at);
                r.pax_seen = true;
                saw_extension = true;
            },
            'g' => {
                var data: std.ArrayList(u8) = .empty;
                defer data.deinit(r.gpa);
                try r.readData(&data, size, at);
                try r.checkRecords(data.items, at);
                try r.mergeGlobal(data.items);
                r.pax_seen = true;
                saw_extension = true;
            },
            'L' => {
                try r.readData(&r.long_name, size, at);
                trimNul(&r.long_name);
                saw_extension = true;
            },
            'K' => {
                try r.readData(&r.long_link, size, at);
                trimNul(&r.long_link);
                saw_extension = true;
            },
            else => return try r.entry(at, flag, size),
        }
    }
}

/// The current entry's contents: exactly `Entry.size` bytes, then
/// `error.EndOfStream`. An `error.ReadFailed` is the archive's input or,
/// when `err()` names one, the archive itself.
pub fn contents(r: *Reader) *Io.Reader {
    return &r.reader.interface;
}

/// The error behind the contents' `error.ReadFailed`, when it was the
/// archive's and not the input's.
pub fn err(r: *const Reader) ?ContentsError {
    return r.reader.failure;
}

/// The current entry's typeflag, for flags that `Entry.Kind` folds.
pub fn typeflag(r: *const Reader) u8 {
    return r.flag;
}

/// The dialect the current entry was written in.
pub fn dialect(r: *const Reader) Format {
    return r.format;
}

/// The current entry's sparse map, empty for a file stored whole.
pub fn segments(r: *const Reader) []const Segment {
    return r.sparse.items;
}

/// The current entry's pax records, then the global ones it takes, in
/// order; a key may appear in both, the first one found applying.
pub fn records(r: *const Reader) Records {
    return .{ .local = .{ .data = r.local.items }, .global = .{ .data = r.global.items } };
}

pub const Records = struct {
    local: pax.Iterator,
    global: pax.Iterator,

    pub fn next(it: *Records) ?pax.Record {
        // Both were checked when they were read.
        if (it.local.next() catch unreachable) |rec| return rec; // unreachable: checked by checkRecords
        return it.global.next() catch unreachable; // unreachable: re-encoded by mergeGlobal
    }
};

/// The current entry's extended attributes: pax `SCHILY.xattr.<name>`
/// records, the values raw.
pub fn xattrs(r: *const Reader) Xattrs {
    return .{ .records = r.records() };
}

pub const Xattrs = struct {
    records: Records,
    pub fn next(it: *Xattrs) ?pax.Record {
        while (it.records.next()) |rec| {
            const lead = "SCHILY.xattr.";
            if (std.mem.startsWith(u8, rec.key, lead) and rec.key.len > lead.len) return .{ .key = rec.key[lead.len..], .value = rec.value };
        }
        return null;
    }
};

//=========================================================================
// Headers

fn fail(r: *Reader, at: u64, reason: Diagnostic.Reason, e: anytype) @TypeOf(e) {
    Diagnostic.set(r.options.diagnostic, r.entries, at, reason);
    return e;
}

/// Reads a whole block; false at the archive's end, exactly between
/// blocks and with no extension header pending.
fn readBlock(r: *Reader, b: *header.Block, pending: bool) NextError!bool {
    const n = r.input.readSliceShort(b) catch return error.ReadFailed;
    r.offset += n;
    if (n == header.block_len) return true;
    if (n == 0 and !pending) return false;
    return r.fail(r.offset, .truncated, error.Truncated);
}

/// An extension header's data, bounded, then its padding.
fn readData(r: *Reader, list: *std.ArrayList(u8), size: u64, at: u64) NextError!void {
    if (Limits.over(r.options.limits.header, size)) return r.fail(at, .header_limit, error.LimitExceeded);
    list.clearRetainingCapacity();
    const n: usize = @intCast(size);
    try list.ensureTotalCapacity(r.gpa, n);
    list.items.len = n;
    r.input.readSliceAll(list.items) catch |e| switch (e) {
        error.EndOfStream => return r.fail(r.offset, .truncated, error.Truncated),
        error.ReadFailed => return error.ReadFailed,
    };
    r.offset += size;
    try r.skipInput(padding(size));
}

/// An extension's data passed over unread, after its bound is checked.
fn skipData(r: *Reader, size: u64, at: u64) NextError!void {
    if (Limits.over(r.options.limits.header, size)) return r.fail(at, .header_limit, error.LimitExceeded);
    try r.skipInput(size);
    try r.skipInput(padding(size));
}

fn checkRecords(r: *Reader, data: []const u8, at: u64) NextError!void {
    var it: pax.Iterator = .{ .data = data };
    while (it.next() catch return r.fail(at, .pax_record, error.Invalid)) |_| {}
}

/// The global records after a `g` header: each key the header names takes
/// its new value, an empty value removing it.
fn mergeGlobal(r: *Reader, data: []const u8) NextError!void {
    var merged: Io.Writer.Allocating = .init(r.gpa);
    defer merged.deinit();
    var old: pax.Iterator = .{ .data = r.global.items };
    while (old.next() catch unreachable) |rec| { // unreachable: re-encoded here
        if (find(data, rec.key) == null) pax.write(&merged.writer, rec.key, rec.value) catch return error.OutOfMemory;
    }
    var new: pax.Iterator = .{ .data = data };
    while (new.next() catch unreachable) |rec| { // unreachable: checked by checkRecords
        if (rec.value.len != 0 and std.mem.eql(u8, find(data, rec.key).?, rec.value))
            pax.write(&merged.writer, rec.key, rec.value) catch return error.OutOfMemory;
    }
    if (Limits.over(r.options.limits.header, merged.writer.end)) return error.LimitExceeded;
    r.global.clearRetainingCapacity();
    try r.global.appendSlice(r.gpa, merged.writer.buffered());
}

/// The last value `data` gives `key`.
fn find(data: []const u8, key: []const u8) ?[]const u8 {
    var it: pax.Iterator = .{ .data = data };
    var found: ?[]const u8 = null;
    while (it.next() catch null) |rec| {
        if (std.mem.eql(u8, rec.key, key)) found = rec.value;
    }
    return found;
}

/// The value an entry takes for `key`: its own record's, else the global
/// one's; an empty local value unsets the global one.
fn value(r: *const Reader, key: []const u8) ?[]const u8 {
    if (find(r.local.items, key)) |v| return if (v.len == 0) null else v;
    return find(r.global.items, key);
}

fn trimNul(list: *std.ArrayList(u8)) void {
    while (list.items.len != 0 and list.items[list.items.len - 1] == 0) list.items.len -= 1;
}

fn padding(size: u64) u64 {
    return (header.block_len - size % header.block_len) % header.block_len;
}

fn skipInput(r: *Reader, n: u64) NextError!void {
    r.input.discardAll64(n) catch |e| switch (e) {
        error.EndOfStream => return r.fail(r.offset, .truncated, error.Truncated),
        error.ReadFailed => return error.ReadFailed,
    };
    r.offset += n;
}

/// Passes over what the caller left of the last entry's data and its
/// padding.
fn skipRest(r: *Reader) NextError!void {
    const c = &r.reader;
    c.interface.seek = 0;
    c.interface.end = 0;
    const rest = c.data_left;
    const pad = c.padding;
    c.data_left = 0;
    c.padding = 0;
    c.logical_left = 0;
    try r.skipInput(rest);
    try r.skipInput(pad);
}

fn number(r: *Reader, field: header.Field, at: u64) NextError!u64 {
    return header.unsigned(field.of(&r.block)) catch r.fail(at, .header_field, error.Invalid);
}

fn paxNumber(r: *Reader, key: []const u8, at: u64) NextError!?u64 {
    const v = r.value(key) orelse return null;
    return std.fmt.parseUnsigned(u64, v, 10) catch r.fail(at, .pax_record, error.Invalid);
}

fn paxTime(r: *Reader, key: []const u8, at: u64) NextError!?Io.Timestamp {
    const v = r.value(key) orelse return null;
    return pax.parseTime(v) catch r.fail(at, .pax_record, error.Invalid);
}

fn headerTime(r: *Reader, field: header.Field, at: u64) NextError!Io.Timestamp {
    const s = header.signed(field.of(&r.block)) catch return r.fail(at, .header_field, error.Invalid);
    return Entry.seconds(s);
}

/// The entry whose header is in `r.block`, with what its extension headers
/// say over what its own fields say.
fn entry(r: *Reader, at: u64, flag: u8, header_size: u64) NextError!Entry {
    if (Limits.full(r.options.limits.entries, r.entries)) return r.fail(at, .entries_limit, error.LimitExceeded);
    const d = header.dialect(&r.block);
    r.flag = flag;
    r.format = if (r.local.items.len != 0 or r.global.items.len != 0) .pax else switch (d) {
        .v7 => .v7,
        .ustar => .ustar,
        .gnu => .gnu,
    };

    // Names: the entry's own pax record, a GNU long header, a global
    // record, then the header's fields.
    var e: Entry = .{ .name = "" };
    const charset_binary = if (r.value("hdrcharset")) |cs| std.mem.eql(u8, cs, "BINARY") else false;
    if (r.value("path")) |p| {
        e.name = p;
        e.encoding = if (charset_binary) .unspecified else .utf8;
    } else if (r.long_name.items.len != 0) {
        e.name = r.long_name.items;
    } else {
        const n = header.string(header.name.of(&r.block));
        const pre = if (d == .ustar) header.string(header.prefix.of(&r.block)) else "";
        if (pre.len != 0) {
            @memcpy(r.joined[0..pre.len], pre);
            r.joined[pre.len] = '/';
            @memcpy(r.joined[pre.len + 1 ..][0..n.len], n);
            e.name = r.joined[0 .. pre.len + 1 + n.len];
        } else e.name = n;
    }
    if (r.value("linkpath")) |l| {
        e.link = l;
    } else if (r.long_link.items.len != 0) {
        e.link = r.long_link.items;
    } else e.link = header.string(header.linkname.of(&r.block));

    e.mode = @intCast((try r.number(header.mode, at)) & 0o7777);
    e.uid = try r.paxNumber("uid", at) orelse try r.number(header.uid, at);
    e.gid = try r.paxNumber("gid", at) orelse try r.number(header.gid, at);
    e.uname = r.value("uname") orelse header.string(header.uname.of(&r.block));
    e.gname = r.value("gname") orelse header.string(header.gname.of(&r.block));
    e.mtime = try r.paxTime("mtime", at) orelse try r.headerTime(header.mtime, at);
    e.atime = try r.paxTime("atime", at);
    e.ctime = try r.paxTime("ctime", at);
    if (d == .gnu) {
        // GNU's times sit where ustar has its prefix; zero means unset.
        if (e.atime == null and !allZeroOrNul(header.gnu_atime.of(&r.block))) e.atime = try r.headerTime(header.gnu_atime, at);
        if (e.ctime == null and !allZeroOrNul(header.gnu_ctime.of(&r.block))) e.ctime = try r.headerTime(header.gnu_ctime, at);
    }
    if (d != .v7) {
        e.device = .{
            .major = std.math.cast(u32, try r.paxNumber("SCHILY.devmajor", at) orelse try r.number(header.devmajor, at)) orelse return r.fail(at, .header_field, error.Invalid),
            .minor = std.math.cast(u32, try r.paxNumber("SCHILY.devminor", at) orelse try r.number(header.devminor, at)) orelse return r.fail(at, .header_field, error.Invalid),
        };
    }

    e.kind = switch (flag) {
        0, '0', '7' => if (d == .v7 and e.name.len != 0 and e.name[e.name.len - 1] == '/') .directory else .file,
        '1' => .hardlink,
        '2' => .symlink,
        '3' => .character_device,
        '4' => .block_device,
        '5', 'D' => .directory,
        '6' => .fifo,
        'S' => .file,
        'V', 'M' => .other,
        // POSIX: an unknown typeflag is read as a regular file.
        else => .file,
    };

    const data_size = try r.paxNumber("size", at) orelse header_size;
    var logical = data_size;
    var sparse = false;
    if (flag == 'S') {
        logical = try r.number(header.gnu_realsize, at);
        try r.oldSparse(at);
        sparse = true;
    } else if (try r.paxSparse(at, data_size)) |real| {
        logical = real.size;
        if (real.name) |n| e.name = n;
        sparse = true;
    }

    // Which entries carry data after their header. A directory, a link or
    // a device carries none whatever its size field says, as libarchive
    // and Go read them (some writers put a size there); a GNU dump
    // directory and a multi-volume continuation carry data no one reads,
    // which is passed over.
    const has_data = switch (e.kind) {
        .file => true,
        .hardlink => r.pax_seen,
        else => false,
    };
    const stored = has_data or flag == 'D' or flag == 'M';
    const c = &r.reader;
    c.* = .{ .interface = c.interface, .input = r.input, .owner = r };
    c.interface.seek = 0;
    c.interface.end = 0;
    c.data_left = if (stored) data_size else 0;
    c.padding = if (stored) padding(data_size) else 0;
    c.logical_left = if (has_data) logical else 0;
    if (sparse) {
        try r.checkSparse(at, logical);
        c.sparse = has_data;
    }
    e.size = if (has_data) logical else 0;
    r.entries += 1;
    return e;
}

fn allZeroOrNul(field: []const u8) bool {
    for (field) |c| if (c != 0 and c != '0' and c != ' ') return false;
    return true;
}

//=========================================================================
// Sparse files

/// The four pairs in an old GNU sparse header and its extension blocks.
fn oldSparse(r: *Reader, at: u64) NextError!void {
    var extended = try r.sparsePairs(r.block[header.gnu_sparse..][0 .. header.gnu_sparse_entries * 24], at);
    extended = extended and r.block[header.gnu_isextended] != 0;
    var ext_bytes: u64 = 0;
    while (extended) {
        var ext: header.Block = undefined;
        if (!try r.readBlock(&ext, true)) unreachable; // unreachable: readBlock fails when pending
        ext_bytes += header.block_len;
        if (Limits.over(r.options.limits.header, ext_bytes)) return r.fail(at, .header_limit, error.LimitExceeded);
        _ = try r.sparsePairs(ext[0 .. header.gnu_ext_entries * 24], at);
        extended = ext[header.gnu_ext_isextended] != 0;
    }
}

/// Appends the (offset, numbytes) pairs of 12-byte fields until an empty
/// one; true if every slot was full.
fn sparsePairs(r: *Reader, area: []const u8, at: u64) NextError!bool {
    var i: usize = 0;
    while (i + 24 <= area.len) : (i += 24) {
        if (area[i] == 0) return false;
        const off = header.unsigned(area[i..][0..12]) catch return r.fail(at, .sparse_map, error.Invalid);
        const len = header.unsigned(area[i + 12 ..][0..12]) catch return r.fail(at, .sparse_map, error.Invalid);
        try r.sparse.append(r.gpa, .{ .offset = off, .len = len });
    }
    return true;
}

const PaxSparse = struct { size: u64, name: ?[]const u8 };

/// A pax sparse file's map (0.0, 0.1 or 1.0), or null for a file stored
/// whole.
fn paxSparse(r: *Reader, at: u64, data_size: u64) NextError!?PaxSparse {
    const major = r.value("GNU.sparse.major");
    if (major) |m| {
        if (!std.mem.eql(u8, m, "1") or !std.mem.eql(u8, r.value("GNU.sparse.minor") orelse "", "0")) return r.fail(at, .sparse_map, error.Invalid);
        const size = try r.paxNumber("GNU.sparse.realsize", at) orelse return r.fail(at, .sparse_map, error.Invalid);
        try r.sparseMapInData(at, data_size);
        return .{ .size = size, .name = r.value("GNU.sparse.name") };
    }
    if (r.value("GNU.sparse.map")) |map| {
        // 0.1: "offset,numbytes,offset,numbytes...".
        const size = try r.paxNumber("GNU.sparse.size", at) orelse return r.fail(at, .sparse_map, error.Invalid);
        if (map.len != 0) {
            var it = std.mem.splitScalar(u8, map, ',');
            while (it.next()) |off_text| {
                const len_text = it.next() orelse return r.fail(at, .sparse_map, error.Invalid);
                const off = std.fmt.parseUnsigned(u64, off_text, 10) catch return r.fail(at, .sparse_map, error.Invalid);
                const len = std.fmt.parseUnsigned(u64, len_text, 10) catch return r.fail(at, .sparse_map, error.Invalid);
                try r.sparse.append(r.gpa, .{ .offset = off, .len = len });
            }
        }
        return .{ .size = size, .name = r.value("GNU.sparse.name") };
    }
    if (r.value("GNU.sparse.size")) |_| {
        // 0.0: the pairs as repeated records of the entry's own header,
        // in order.
        const size = try r.paxNumber("GNU.sparse.size", at) orelse unreachable; // unreachable: present
        var it: pax.Iterator = .{ .data = r.local.items };
        var pending: ?u64 = null;
        while (it.next() catch unreachable) |rec| { // unreachable: checked by checkRecords
            if (std.mem.eql(u8, rec.key, "GNU.sparse.offset")) {
                if (pending != null) return r.fail(at, .sparse_map, error.Invalid);
                pending = std.fmt.parseUnsigned(u64, rec.value, 10) catch return r.fail(at, .sparse_map, error.Invalid);
            } else if (std.mem.eql(u8, rec.key, "GNU.sparse.numbytes")) {
                const off = pending orelse return r.fail(at, .sparse_map, error.Invalid);
                const len = std.fmt.parseUnsigned(u64, rec.value, 10) catch return r.fail(at, .sparse_map, error.Invalid);
                try r.sparse.append(r.gpa, .{ .offset = off, .len = len });
                pending = null;
            }
        }
        if (pending != null) return r.fail(at, .sparse_map, error.Invalid);
        return .{ .size = size, .name = r.value("GNU.sparse.name") };
    }
    return null;
}

/// 1.0's map, at the start of the data: decimal lines, the count first,
/// padded to a block; what follows is the data.
fn sparseMapInData(r: *Reader, at: u64, data_size: u64) NextError!void {
    var used: u64 = 0;
    var line: [24]u8 = undefined;
    const count = try r.mapLine(&line, &used, at, data_size);
    if (Limits.over(r.options.limits.header, count *| 16)) return r.fail(at, .header_limit, error.LimitExceeded);
    for (0..@intCast(count)) |_| {
        const off = try r.mapLine(&line, &used, at, data_size);
        const len = try r.mapLine(&line, &used, at, data_size);
        try r.sparse.append(r.gpa, .{ .offset = off, .len = len });
    }
    const pad = padding(used);
    if (used + pad > data_size) return r.fail(at, .sparse_map, error.Invalid);
    try r.skipInput(pad);
    used += pad;
    // The data now starts after the map; the entry's data shrinks by it.
    r.map_used = used;
}

/// A number of the map, on a line of its own. Lines starting with `#`
/// before it are comments (`#!gnu-sparse-format`, `#format:1.0`), as
/// libarchive reads them.
fn mapLine(r: *Reader, line: *[24]u8, used: *u64, at: u64, data_size: u64) NextError!u64 {
    var n: usize = 0;
    var comment = false;
    while (true) {
        if (used.* >= data_size or n == line.len) return r.fail(at, .sparse_map, error.Invalid);
        const c = r.input.takeByte() catch |e| switch (e) {
            error.EndOfStream => return r.fail(r.offset, .truncated, error.Truncated),
            error.ReadFailed => return error.ReadFailed,
        };
        r.offset += 1;
        used.* += 1;
        if (n == 0 and !comment and c == '#') {
            comment = true;
        } else if (comment) {
            if (c == '\n') comment = false;
        } else if (c == '\n') {
            break;
        } else {
            line[n] = c;
            n += 1;
        }
    }
    return std.fmt.parseUnsigned(u64, line[0..n], 10) catch r.fail(at, .sparse_map, error.Invalid);
}

/// Runs in order, apart, inside the file, and within the data the archive
/// stores.
fn checkSparse(r: *Reader, at: u64, logical: u64) NextError!void {
    const c = &r.reader;
    c.data_left -= r.map_used;
    c.padding = padding(c.data_left + r.map_used);
    r.map_used = 0;
    var end: u64 = 0;
    var stored: u64 = 0;
    for (r.sparse.items) |s| {
        if (s.offset < end) return r.fail(at, .sparse_map, error.Invalid);
        end = std.math.add(u64, s.offset, s.len) catch return r.fail(at, .sparse_map, error.Invalid);
        if (end > logical) return r.fail(at, .sparse_map, error.Invalid);
        stored += s.len;
    }
    // Bytes past the last run are passed over, as libarchive passes them.
    if (stored > c.data_left) return r.fail(at, .sparse_map, error.Invalid);
}

//=========================================================================
// Contents

pub const ContentsError = error{
    /// The archive ended inside the entry's data.
    Truncated,
};

/// The current entry's contents, as a `std.Io.Reader`.
const Contents = struct {
    interface: Io.Reader,
    input: *Io.Reader = undefined,
    owner: *Reader = undefined,
    /// The archive's data bytes left, map and runs included.
    data_left: u64 = 0,
    padding: u64 = 0,
    /// The contents' bytes left, holes included.
    logical_left: u64 = 0,
    /// The contents' position, for the sparse map.
    position: u64 = 0,
    sparse: bool = false,
    run: usize = 0,
    failure: ?ContentsError = null,

    const vtable: Io.Reader.VTable = .{ .stream = stream, .discard = discard };

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const c: *Contents = @fieldParentPtr("interface", io_r);
        if (c.logical_left == 0) return error.EndOfStream;
        const span = c.next();
        const want = limit.min(.limited64(span.len));
        if (span.hole) {
            // A hole may be gigabytes: written a piece at a time.
            const n = want.minInt(64 * 1024);
            try w.splatByteAll(0, n);
            c.advance(n, false);
            return n;
        }
        const n = c.input.stream(w, want) catch |e| switch (e) {
            error.EndOfStream => return c.truncated(),
            else => |other| return other,
        };
        c.advance(n, true);
        return n;
    }

    fn discard(io_r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
        const c: *Contents = @fieldParentPtr("interface", io_r);
        if (c.logical_left == 0) return error.EndOfStream;
        const span = c.next();
        const want = limit.min(.limited64(span.len));
        if (span.hole) {
            c.advance(@backingInt(want), false);
            return @backingInt(want);
        }
        const n = c.input.discard(want) catch |e| switch (e) {
            error.EndOfStream => return c.truncated(),
            else => |other| return other,
        };
        c.advance(n, true);
        return n;
    }

    fn truncated(c: *Contents) error{ReadFailed} {
        c.failure = error.Truncated;
        Diagnostic.set(c.owner.options.diagnostic, c.owner.entries -| 1, c.owner.offset, .truncated);
        return error.ReadFailed;
    }

    const Span = struct { hole: bool, len: u64 };

    /// What comes next: stored bytes or a hole, and how many.
    fn next(c: *Contents) Span {
        if (!c.sparse) return .{ .hole = false, .len = c.logical_left };
        const runs = c.owner.sparse.items;
        while (c.run < runs.len and runs[c.run].offset + runs[c.run].len <= c.position) c.run += 1;
        if (c.run == runs.len) return .{ .hole = true, .len = c.logical_left };
        const s = runs[c.run];
        if (c.position < s.offset) return .{ .hole = true, .len = s.offset - c.position };
        return .{ .hole = false, .len = s.offset + s.len - c.position };
    }

    fn advance(c: *Contents, n: usize, stored: bool) void {
        c.position += n;
        c.logical_left -= n;
        if (stored) {
            c.data_left -= n;
            c.owner.offset += n;
        }
    }
};
