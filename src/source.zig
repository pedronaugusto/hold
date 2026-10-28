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

    /// A reader of its own, at its own position however many are open: a
    /// positional reader of the file, or a view of the memory.
    pub const View = union { file: Io.File.Reader, memory: Io.Reader };

    /// A reader from `offset` on that moves no other reader of the source,
    /// for streams read side by side (a 7z folder's packed streams).
    /// `buffer` is a file reader's.
    pub fn independentAt(s: Source, offset: u64, view: *View, buffer: []u8) error{ReadFailed}!*Io.Reader {
        switch (s) {
            .file => |fr| {
                view.* = .{ .file = .initSize(fr.file, fr.io, buffer, fr.size) };
                view.file.seekTo(offset) catch return error.ReadFailed;
                return &view.file.interface;
            },
            .memory => |m| {
                view.* = .{ .memory = .fixed(m[@intCast(@min(offset, m.len))..]) };
                return &view.memory;
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
