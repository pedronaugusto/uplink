//! Test-only: the `Io` the tests run on. `zig build test` runs the suite on
//! `std.testing.io`, which is `Io.Threaded`, and on a reactor runtime, the
//! evented `Io` uplink is built for, once on each kernel backend the target
//! has (io_uring and epoll on Linux, kqueue on macOS and the BSDs, IOCP on
//! Windows). The test binary says at build time which it was built for
//! (`build.zig`). The runtime is made at first use and lives until the
//! process ends, since every test finishes its tasks before it returns.

const std = @import("std");
const reactor = @import("reactor");
const config = @import("test_io");
const Io = std.Io;

var starting: std.atomic.Mutex = .unlocked;
var started: std.atomic.Value(bool) = .init(false);
var runtime: reactor.Runtime = undefined;

/// The `Io` for the test running now.
pub fn io() Io {
    if (comptime !evented) return std.testing.io;
    if (!started.load(.acquire)) start();
    return runtime.io();
}

/// Whether the suite is on the reactor runtime.
pub const evented = config.backend != null;

/// The reactor backend the suite runs on, when it is evented.
pub const backend: ?reactor.Runtime.Backend = if (config.backend) |name|
    std.meta.stringToEnum(reactor.Runtime.Backend, name) orelse @compileError("no reactor backend " ++ name)
else
    null;

fn start() void {
    while (!starting.tryLock()) std.atomic.spinLoopHint();
    defer starting.unlock();
    if (started.load(.acquire)) return;
    // Workers beside the home thread, so what a test starts runs in
    // parallel as in a program; the lanes small, since a test needs a name
    // looked up or a file read now and then. A backend the system lacks
    // fails the run: the run is that backend's evidence.
    runtime.init(std.heap.page_allocator, .{
        .backend = backend.?,
        .workers = 3,
        .environ = std.testing.environ,
        .offload = .{ .owned = .{ .sync = 2, .lookup = 2, .wait = 4, .general = 2 } },
        // No stall reports: a Debug build's handshake or compression holds
        // its processor past the default 10 ms on a loaded machine, and
        // the report is the scheduler's latency, not something of
        // uplink's a test proves.
        .report_after = null,
    }) catch |err| std.debug.panic("the evented test runtime on {t}: {t}", .{ backend.?, err });
    runtime.start() catch |err| std.debug.panic("the evented test runtime on {t}: {t}", .{ backend.?, err });
    started.store(true, .release);
}
