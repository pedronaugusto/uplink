//! Test-only: the `Io` the tests run on. `zig build test` runs the suite on
//! `std.testing.io`, which is `Io.Threaded`, and on a reactor runtime, the
//! evented `Io` uplink is built for, once on each kernel backend the target
//! has (io_uring and epoll on Linux, kqueue on macOS and the BSDs, IOCP on
//! Windows). The test binary says at build time which it was built for
//! (`build.zig`). The runtime is made at first use and lives until the
//! process ends, since every test finishes its tasks before it returns.
//!
//! The client and server suites run on shakedown's simulated network
//! (`simulated`), once, in the `Io.Threaded` binary; the evented binaries
//! skip them. What meets the system's sockets on every backend is the
//! conformance suite (`conformance_test.zig`, one round trip per feature)
//! and the tests of what only the system shows: the system's peek, named
//! pipes, timed reads and connects, and interop with openssl and curl. A
//! socket reactor makes past the `Io` (a bind, an option before the connect)
//! is made on the simulation through reactor's seam, its options told there.

const std = @import("std");
const reactor = @import("reactor");
const shakedown = @import("shakedown");
const reactor_testing = @import("reactor.testing");
const config = @import("test_io");
const Io = std.Io;

/// The node's `Io` while a test body runs under `simulated`.
var simulating: ?Io = null;
/// The node's seam while a test body runs under `simulated`.
var node_seam: ?*reactor_testing.Seam = null;

var starting: std.atomic.Mutex = .unlocked;
var started: std.atomic.Value(bool) = .init(false);
var runtime: reactor.Runtime = undefined;

/// The `Io` for the test running now.
pub fn io() Io {
    if (simulating) |node| return node;
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

/// The socket options reactor told the node's seam so far, under `simulated`
/// (`reactor.testing`'s `asked()`): they are recorded there, never set.
pub fn asked() reactor_testing.Seam.Asked {
    return node_seam.?.asked();
}

/// A test's own `Io` layer over `io()` (a `FaultIo`, a counting one) with the
/// node's seam in front of it again while simulating: reactor finds the seam
/// only in the outermost layer. The layer itself when not simulating.
pub const Seamed = struct {
    seam: reactor_testing.Seam = undefined,

    pub fn over(s: *Seamed, layer: Io) Io {
        if (simulating == null) return layer;
        s.seam.init(layer);
        return s.seam.io();
    }
};

/// Runs `body` with `args` as the root task of a simulation on one node of
/// shakedown's simulated network, `io()` that node's `Io` through reactor's
/// seam (reactor's raw socket calls ask the test). A loopback address is the
/// node itself, so a test's server on 127.0.0.1 and its client meet as on a
/// machine, in virtual time, with nothing of the system's network. A body
/// that fails fails the test; one left waiting with nothing to wake it is a
/// deadlock, reported with what each task waits on. Run in the `Io.Threaded`
/// binary alone: a simulation brings its own `Io`, so the evented binaries
/// would only run it again (the conformance tests that stay on the system's
/// sockets are theirs).
pub fn simulated(comptime body: anytype, args: anytype) !void {
    if (evented) return error.SkipZigTest;
    // A thread's stack, as the system gives a test's: a Debug build's TLS
    // key share and Brotli decoder state outgrow a task's default 256 KiB.
    // The wall clock starts an hour past the system's: a fixture the system
    // makes while the body runs (a certificate openssl dates from its own
    // now, seconds after this start) is valid inside, as it is outside.
    const sim = try shakedown.Sim.init(std.testing.allocator, .{
        .watchdog = null,
        .seed = 1,
        .stack_size = .fromRaw(8 << 20),
        .clock = .{ .real = Io.Clock.real.now(std.testing.io).addDuration(.fromSeconds(60 * 60)) },
    });
    defer sim.deinit();
    const node = try sim.node("test", .{});
    var seam: reactor_testing.Seam = undefined;
    seam.init(node.io());
    simulating = seam.io();
    node_seam = &seam;
    defer {
        simulating = null;
        node_seam = null;
    }
    const outcome = sim.run(body, args);
    switch (outcome) {
        .finished => {},
        .failed => |err| return err,
        .deadlock => |reports| {
            std.debug.print("deadlock, {d} tasks waiting\n", .{reports.len});
            for (reports) |report| std.debug.print("  node {d}: {f}", .{ report.node.raw(), report });
            return error.TestUnexpectedResult;
        },
        .stuck, .double_close => |report| {
            std.debug.print("{t}: node {d}: {f}", .{ outcome, report.node.raw(), report });
            return error.TestUnexpectedResult;
        },
        else => {
            std.debug.print("{t}\n", .{outcome});
            return error.TestUnexpectedResult;
        },
    }
}
