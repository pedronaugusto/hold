//! The archives' times as aegis instants, each conversion carrying its
//! unit: whole Unix seconds (tar headers, zip's Unix fields and DOS
//! times), pax's seconds and nanoseconds, and Windows FILETIME (7z and
//! zip's NTFS field), to and from `Io.Timestamp`.
const std = @import("std");
const Io = std.Io;
const aegis = @import("aegis");

/// Unix time in whole seconds.
const Seconds = aegis.units.Instant(.real, .second, i64);
/// Unix time in nanoseconds, as `Io.Timestamp` holds it.
const Nanoseconds = aegis.units.Instant(.real, .nanosecond, i96);
/// A time's magnitude in nanoseconds, for pax's sign-and-magnitude text.
const Magnitude = aegis.units.Instant(.real, .nanosecond, u96);
const Span = aegis.units.Duration(.nanosecond, i96);

/// 1601-01-01, FILETIME's zero.
const windows_epoch = Seconds.fromRaw(-11_644_473_600).convert(.nanosecond, i96, .exact);

/// A timestamp from whole seconds since the epoch.
pub fn fromSeconds(s: i64) Io.Timestamp {
    return Seconds.fromRaw(s).toTimestamp();
}

/// `t`'s whole seconds since the epoch, rounded toward the past.
pub fn wholeSeconds(t: Io.Timestamp) i96 {
    return Nanoseconds.fromTimestamp(t, .exact).convert(.second, i96, .down).raw();
}

/// Whether `t` falls on a whole second.
pub fn isWhole(t: Io.Timestamp) bool {
    _ = Nanoseconds.fromTimestamp(t, .exact).convert(.second, i96, .exact) catch return false;
    return true;
}

/// A Windows FILETIME, 100 ns ticks since 1601, as a timestamp.
pub fn fromFiletime(ticks: u64) Io.Timestamp {
    return windows_epoch.saturatingAdd(Span.fromRaw(ticks).saturatingMul(100)).toTimestamp();
}

/// A time as pax writes it: a sign, then the magnitude's whole seconds and
/// the nanoseconds past them.
pub const Parts = struct { negative: bool, whole: u96, nanos: u96 };

/// The time pax's text names: `whole` seconds and `nanos` past them, before
/// the epoch when `negative`.
pub fn fromParts(negative: bool, whole: i64, nanos: u32) Io.Timestamp {
    const magnitude = aegis.units.Duration(.second, i64).fromRaw(whole).convert(.nanosecond, i96, .exact).saturatingAdd(Span.fromRaw(nanos));
    const signed = if (negative) Span.fromRaw(0).saturatingSub(magnitude) else magnitude;
    return Nanoseconds.fromRaw(0).saturatingAdd(signed).toTimestamp();
}

/// `t` as pax writes it.
pub fn parts(t: Io.Timestamp) Parts {
    const ns = Nanoseconds.fromTimestamp(t, .exact).raw();
    // The most negative time's magnitude has no positive i96.
    const magnitude = Magnitude.fromRaw(@abs(ns));
    const second = magnitude.floor(.literal("1s"));
    return .{
        .negative = ns < 0,
        .whole = magnitude.convert(.second, u96, .down).raw(),
        .nanos = second.saturatingDurationTo(magnitude).raw(),
    };
}

test "FILETIME's zero is 1601, its tick 100 ns" {
    try std.testing.expectEqual(@as(i96, -11_644_473_600), wholeSeconds(fromFiletime(0)));
    try std.testing.expectEqual(@as(i96, 0), wholeSeconds(fromFiletime(116_444_736_000_000_000)));
    try std.testing.expect(!isWhole(fromFiletime(116_444_736_000_000_001)));
}

test "pax's parts both ways, before the epoch too" {
    const t = fromParts(true, 1, 250_000_000);
    try std.testing.expectEqual(@as(i96, -2), wholeSeconds(t));
    try std.testing.expectEqual(Parts{ .negative = true, .whole = 1, .nanos = 250_000_000 }, parts(t));
    const min: Io.Timestamp = .fromNanoseconds(std.math.minInt(i96));
    try std.testing.expect(parts(min).negative);
}
