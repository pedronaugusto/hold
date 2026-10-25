//! Where a random-access archive's bytes are: a file or memory. zip's
//! central directory and 7z's header are found by offset, and each
//! entry's data is read from where the archive says it starts.
const std = @import("std");
const Io = std.Io;

pub const Source = union(enum) {
    /// The archive's while it is open: an entry's reader moves it.
    file: *Io.File.Reader,
    memory: []const u8,

    pub const Error = error{ Truncated, ReadFailed };

    pub fn size(s: Source) error{ReadFailed}!u64 {
        return switch (s) {
            .file => |fr| fr.getSize() catch error.ReadFailed,
            .memory => |m| m.len,
        };
    }

    /// Exactly `out.len` bytes at `offset`.
    pub fn readAt(s: Source, offset: u64, out: []u8) Error!void {
        switch (s) {
            .file => |fr| {
                fr.seekTo(offset) catch return error.ReadFailed;
                fr.interface.readSliceAll(out) catch |e| return switch (e) {
                    error.EndOfStream => error.Truncated,
                    error.ReadFailed => error.ReadFailed,
                };
            },
            .memory => |m| {
                if (offset > m.len or out.len > m.len - offset) return error.Truncated;
                @memcpy(out, m[@intCast(offset)..][0..out.len]);
            },
        }
    }

    /// A reader from `offset` on: the file's own, moved there, or `view`
    /// over the memory.
    pub fn readerAt(s: Source, offset: u64, view: *Io.Reader) error{ReadFailed}!*Io.Reader {
        switch (s) {
            .file => |fr| {
                fr.seekTo(offset) catch return error.ReadFailed;
                return &fr.interface;
            },
            .memory => |m| {
                view.* = .fixed(m[@intCast(@min(offset, m.len))..]);
                return view;
            },
        }
    }
};
