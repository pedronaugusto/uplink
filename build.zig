const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    //=====================================================================
    // The module. Pure Zig, `std` only: nothing to link and no build
    // options, so nothing a consumer has to match.
    //=====================================================================

    const module = b.addModule("uplink", .{
        .root_source_file = b.path("src/uplink.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Everything below is uplink's own: a project depending on uplink
    // neither needs nor fetches shakedown or preflight.
    if (b.dep_prefix.len != 0) return;

    //=====================================================================
    // Tests. shakedown is a lazy, test-only dependency: production uplink
    // imports nothing of ours.
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
    const tests = b.addTest(.{
        .name = "uplink-tests",
        .filters = if (test_filter) |filter| &.{filter} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.addImport("std_tls_client", std_client_module);
    if (b.dependencyLazy("shakedown", .{ .target = target, .optimize = optimize })) |shakedown| {
        tests.root_module.addImport("shakedown", shakedown.module("shakedown"));
    } else |_| {}

    const test_step = b.step("test", "Run the tests and the example");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const check_step = b.step("check", "Compile the tests, example and benchmarks without running them");
    check_step.dependOn(&tests.step);

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
            .imports = &.{.{ .name = "uplink", .module = module }},
        }),
    });
    const example_run = b.addRunArtifact(example);
    example_run.setCwd(b.path("."));
    const examples_step = b.step("examples", "Build and run the usage example");
    examples_step.dependOn(&example_run.step);
    test_step.dependOn(examples_step);
    check_step.dependOn(&example.step);

    //=====================================================================
    // Benchmarks: run by hand with `zig build bench`, compiled by CI and
    // never timed there. Results are JSON lines under zig-out/bench/.
    //=====================================================================

    const bench = b.addExecutable(.{
        .name = "uplink-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = if (optimize == .debug) .fast else optimize,
            .imports = &.{.{ .name = "uplink", .module = module }},
        }),
    });
    const bench_run = b.addRunArtifact(bench);
    bench_run.setCwd(b.path("."));
    bench_run.addPassthruArgs();
    b.step("bench", "Run the benchmarks (by hand; never timed in CI)").dependOn(&bench_run.step);
    check_step.dependOn(&bench.step);

    b.getInstallStep().dependOn(check_step);

    //=====================================================================
    // CI wiring. preflight is lazy and only this tree asks for it.
    //=====================================================================

    if (b.lazyImport(@This(), "preflight")) |preflight| {
        preflight.addCi(b, .{ .tests = test_step, .portable_tests = true });
        // A project that depends on uplink by path, with no packages to
        // fetch: the build a consumer gets.
        preflight.addConsumerCheck(b, .{ .package = "uplink", .program = b.path("ci/consumer.zig") });
    }
}
