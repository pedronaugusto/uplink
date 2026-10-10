const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    //=====================================================================
    // The module. Pure Zig, `std`, aegis and reactor: nothing to link and no
    // build options, so nothing a consumer has to match. reactor is the
    // family's evented `std.Io` and owns the sockets' deadlines, name lookup
    // and connecting; uplink runs on any `Io`, and on reactor's it needs no
    // task of its own to keep a deadline.
    //=====================================================================

    const aegis = b.dependency("aegis", .{ .target = target, .optimize = optimize });
    const reactor = b.dependency("reactor", .{ .target = target, .optimize = optimize });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "aegis", .module = aegis.module("aegis") },
        .{ .name = "reactor", .module = reactor.module("reactor") },
    };

    const module = b.addModule("uplink", .{
        .root_source_file = b.path("src/uplink.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });

    // Everything below is uplink's own: a project depending on uplink
    // neither needs nor fetches shakedown or preflight.
    if (b.dep_prefix.len != 0) return;

    //=====================================================================
    // Tests. shakedown is a lazy, test-only dependency: production uplink
    // imports aegis alone.
    //=====================================================================

    // The standard library's TLS client, which `src/tls/Client.zig` is a
    // copy of with client authentication added: the fork check holds the
    // copy to it, and fails when the compiler building this ships another.
    // A copy of the file is embedded rather than its path, so the test
    // binary's cache key follows the bytes, not the toolchain's location.
    const std_tls_client = b.graph.path(.zig_lib, "std/crypto/tls/Client.zig");
    const std_client = b.addWriteFiles();
    _ = std_client.addCopyFile(std_tls_client, "Client.zig.txt");
    const std_client_module = b.createModule(.{
        .root_source_file = std_client.add("std_tls_client.zig", "pub const source = @embedFile(\"Client.zig.txt\");\n"),
    });

    const test_filter = b.option([]const u8, "test-filter", "Select tests by name");
    var shakedown: ?*std.Build.Module = null;
    if (b.dependencyLazy("shakedown", .{ .target = target, .optimize = optimize })) |dep| {
        shakedown = dep.module("shakedown");
    } else |_| {}
    const test_inputs: TestInputs = .{
        .target = target,
        .optimize = optimize,
        .imports = imports,
        .std_tls_client = std_client_module,
        .shakedown = shakedown,
        .filter = test_filter,
    };
    // The suite runs twice: on `Io.Threaded`, which `std.testing.io` is, and
    // on a reactor runtime, the evented `Io` uplink is built for. One after
    // the other, so neither loads the machine the other's timers run on.
    const tests = addTests(b, "uplink-tests", false, test_inputs);
    const evented_tests = addTests(b, "uplink-tests-evented", true, test_inputs);

    const test_step = b.step("test", "Run the tests and the example");
    const tests_run = b.addRunArtifact(tests);
    const evented_run = b.addRunArtifact(evented_tests);
    evented_run.step.dependOn(&tests_run.step);
    test_step.dependOn(&tests_run.step);
    test_step.dependOn(&evented_run.step);

    const check_step = b.step("check", "Compile the tests and the example without running them");
    check_step.dependOn(&tests.step);
    check_step.dependOn(&evented_tests.step);

    // The TLS fork against std and its recorded diff, alone.
    const fork_tests = b.addTest(.{
        .name = "uplink-tls-fork",
        .filters = &.{"the TLS client is std's, with the recorded diff and nothing else"},
        .root_module = tests.root_module,
    });
    b.step("check-tls-fork", "Verify the TLS fork against std and its recorded diff").dependOn(&b.addRunArtifact(fork_tests).step);

    // Re-record the diff after bringing a new std's changes across.
    const fork_writer = b.addExecutable(.{
        .name = "tls-fork",
        .root_module = b.createModule(.{ .root_source_file = b.path("ci/tls_fork.zig"), .target = b.graph.host, .optimize = .safe }),
    });
    const fork_options = b.addOptions();
    fork_options.addOptionPath("std_tls_client", std_tls_client);
    fork_writer.root_module.addOptions("build_options", fork_options);
    const fork_run = b.addRunArtifact(fork_writer);
    fork_run.setCwd(b.path("."));
    b.step("tls-fork", "Re-record the TLS client's diff against std").dependOn(&fork_run.step);

    //=====================================================================
    // Example: built AND run against the module a consumer gets.
    // examples/usage.zig is also README.md's Usage block (zig build docs --
    // usage), so the snippet a reader copies is code CI executes.
    //=====================================================================

    const example = b.addExecutable(.{
        .name = "usage",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/usage.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "uplink", .module = module },
                .{ .name = "reactor", .module = reactor.module("reactor") },
            },
        }),
    });
    const example_run = b.addRunArtifact(example);
    example_run.setCwd(b.path("."));
    const examples_step = b.step("examples", "Build and run the usage example");
    examples_step.dependOn(&example_run.step);
    test_step.dependOn(examples_step);
    check_step.dependOn(&example.step);

    b.getInstallStep().dependOn(check_step);

    //=====================================================================
    // CI wiring. preflight is lazy and only this tree asks for it.
    //=====================================================================

    if (b.lazyImport(@This(), "preflight")) |preflight| {
        preflight.addCi(b, .{
            .tests = test_step,
            .portable_tests = true,
            // uplink's own measurements, in bench/: `zig build bench` builds
            // them in ReleaseFast and runs them, and `zig build test` runs
            // each once with `--smoke`.
            .bench = .{
                .programs = &.{.{ .name = "uplink-bench", .source = "bench/main.zig" }},
                .imports = benchImports,
                .target = target,
                .optimize = optimize,
            },
        });
        // A project that depends on uplink by path, with only aegis and
        // reactor to fetch: the build a consumer gets.
        preflight.addConsumerCheck(b, .{ .package = "uplink", .program = b.path("ci/consumer.zig"), .packages = &.{ aegis, reactor } });
    }
}

/// uplink in the mode a benchmark builds in: an imported module keeps its
/// own mode, so a ReleaseFast benchmark over the Debug module would time
/// the Debug module.
fn benchImports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) []const std.Build.Module.Import {
    const uplink = b.createModule(.{ .root_source_file = b.path("src/uplink.zig"), .target = target, .optimize = optimize });
    uplink.addImport("aegis", b.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis"));
    const reactor = b.dependency("reactor", .{ .target = target, .optimize = optimize }).module("reactor");
    uplink.addImport("reactor", reactor);
    // Select uplink's published measuring pin rather than preflight's default.
    const shakedown = b.dependency("shakedown", .{ .target = target, .optimize = optimize });
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "uplink", .module = uplink },
        .{ .name = "reactor", .module = reactor },
        .{ .name = "shakedown", .module = shakedown.module("shakedown") },
    }) catch @panic("OOM");
}

/// What both builds of the test suite are made from.
const TestInputs = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    imports: []const std.Build.Module.Import,
    std_tls_client: *std.Build.Module,
    shakedown: ?*std.Build.Module,
    filter: ?[]const u8,
};

/// The test suite, running on `std.testing.io` or, `evented`, on a reactor
/// runtime (`src/testing/io.zig` says which it was built for).
fn addTests(b: *std.Build, name: []const u8, evented: bool, inputs: TestInputs) *std.Build.Step.Compile {
    const tests = b.addTest(.{
        .name = name,
        .filters = if (inputs.filter) |filter| &.{filter} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = inputs.target,
            .optimize = inputs.optimize,
            .imports = inputs.imports,
        }),
    });
    tests.root_module.addImport("std_tls_client", inputs.std_tls_client);
    if (inputs.shakedown) |module| tests.root_module.addImport("shakedown", module);
    const io = b.addOptions();
    io.addOption(bool, "evented", evented);
    tests.root_module.addOptions("test_io", io);
    return tests;
}
