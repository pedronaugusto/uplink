//! Test-only: the `Io` the tests run on. `zig build test` runs the suite
//! twice: on `std.testing.io`, which is `Io.Threaded`, and on a reactor
//! runtime, the evented `Io` uplink is built for. The test binary says which
//! at build time (`build.zig`); the runtime is made at first use and lives
//! until the process ends, since every test finishes its tasks before it
//! returns.

const std = @import("std");
const reactor = @import("reactor");
const config = @import("test_io");
const Io = std.Io;

var starting: std.atomic.Mutex = .unlocked;
var started: std.atomic.Value(bool) = .init(false);
var runtime: reactor.Runtime = undefined;

/// The `Io` for the test running now.
pub fn io() Io {
    if (comptime !config.evented) return std.testing.io;
    if (!started.load(.acquire)) start();
    return runtime.io();
}

/// Whether the suite is on the reactor runtime.
pub const evented = config.evented;

fn start() void {
    while (!starting.tryLock()) std.atomic.spinLoopHint();
    defer starting.unlock();
    if (started.load(.acquire)) return;
    // Workers beside the home thread, so what a test starts runs in
    // parallel as in a program; the lanes small, since a test needs a name
    // looked up or a file read now and then.
    runtime.init(std.heap.page_allocator, .{
        .workers = 3,
        .environ = std.testing.environ,
        .offload = .{ .owned = .{ .sync = 2, .lookup = 2, .wait = 4, .general = 2 } },
    }) catch |err| std.debug.panic("the evented test runtime: {t}", .{err});
    runtime.start() catch |err| std.debug.panic("the evented test runtime: {t}", .{err});
    started.store(true, .release);
}
