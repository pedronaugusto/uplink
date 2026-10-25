//! uplink's lock-free cells: what it counts as it goes, how many of a thing
//! are open now, and the flags a task sets once. Each is aegis's atomic cell
//! over a domain of its own, read and written whole and never as the integer
//! behind it.

const aegis = @import("aegis");

/// A number of events: connections made, requests served, timeouts that
/// could not be kept. Added to one at a time, it never reaches 2^64.
pub const Events = aegis.units.Count(enum { events }, u64);
/// A count of events, without a lock.
pub const Counter = aegis.Atomic(Events);

/// How many of a thing there are now: connections open or held.
pub const Level = aegis.units.Count(enum { level }, u32);
/// A level, without a lock.
pub const Gauge = aegis.Atomic(Level);

/// A flag that is set once, or claimed by the one task that sets it first.
pub const Flag = enum(u8) { clear, set };
/// A flag, without a lock.
pub const Latch = aegis.Atomic(Flag);

/// Count one more event.
pub fn bump(counter: *Counter) void {
    _ = counter.fetchAddWrapping(.fromRaw(1), .monotonic);
}
