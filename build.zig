const std = @import("std");

/// What a project that depends on uplink builds: `uplink.wire`, the codecs, and
/// with the client (the default) `uplink`, which fetches reactor and cloak.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    //=====================================================================
    // The modules. Pure Zig, `std`, aegis, reactor and cloak. Two are
    // published. `uplink.wire` is the codecs, sans I/O, and imports `std`
    // and aegis alone. `uplink` is everything: the client on top of the
    // codecs, with reactor, the family's evented `std.Io`, which owns the
    // sockets' deadlines, name lookup and connecting (uplink runs on any
    // `Io`, and on reactor's it needs no task of its own to keep a deadline),
    // and cloak, the family's TLS, whose system trust links the platform's
    // own libraries on macOS and Windows.
    //
    // reactor and cloak are fetched lazily, and only for the client. The one
    // build option, `client`, is true unless a project says otherwise: a
    // project that builds an HTTP client writes nothing extra, and one that
    // only reads and writes HTTP messages sets `.client = false`, fetches no
    // reactor or cloak, and finds `uplink.wire` alone.
    //=====================================================================

    const with_client = b.option(bool, "client", "Build the HTTP client and the `uplink` module, which fetch reactor; false leaves `uplink.wire` alone") orelse true;
    const aegis = b.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis");
    const reactor: ?*std.Build.Module = if (with_client) if (b.dependencyLazy("reactor", .{ .target = target, .optimize = optimize })) |package| package.module("reactor") else |_| null else null;
    const cloak: ?*std.Build.Module = if (with_client) if (b.dependencyLazy("cloak", .{ .target = target, .optimize = optimize })) |package| package.module("cloak") else |_| null else null;
    _ = uplinkModules(b, target, optimize, aegis, with_client, reactor, cloak);
}

/// uplink's development: its tests, example, checks and benchmarks, under
/// preflight's gate. Run through bay.
pub fn dev(b: *std.Build, tools: type) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const preflight = tools.preflight;
    const package = b.dependency("uplink", .{ .target = target, .optimize = optimize });
    const p = package.builder;
    const aegis_package = p.dependency("aegis", .{ .target = target, .optimize = optimize });
    const aegis = aegis_package.module("aegis");
    // reactor and cloak are lazy: their error ends this configure pass until they are fetched.
    const reactor_package = p.dependencyLazy("reactor", .{ .target = target, .optimize = optimize }) catch return;
    const cloak_package = p.dependencyLazy("cloak", .{ .target = target, .optimize = optimize }) catch return;
    const reactor = reactor_package.module("reactor");
    const cloak = cloak_package.module("cloak");
    const shakedown = b.dependency("shakedown", .{ .target = target, .optimize = optimize });

    const module = package.module("uplink");
    const wire = package.module("uplink.wire");
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "aegis", .module = aegis },
        .{ .name = "reactor", .module = reactor },
        .{ .name = "cloak", .module = cloak },
        .{ .name = "uplink.wire", .module = wire },
    };

    //=====================================================================
    // Tests. shakedown is a dev dependency: production uplink
    // imports aegis alone.
    //=====================================================================

    const test_filter = b.option([]const u8, "test-filter", "Select tests by name");
    const test_inputs: TestInputs = .{
        .target = target,
        .optimize = optimize,
        .imports = imports,
        .shakedown = shakedown.module("shakedown"),
        .package = p,
        .filter = test_filter,
    };
    // The suite runs twice: on `Io.Threaded`, which `std.testing.io` is, and
    // on a reactor runtime, the evented `Io` uplink is built for. One after
    // the other, so neither loads the machine the other's timers run on.
    const tests = addTests(b, "uplink-tests", false, test_inputs);
    const evented_tests = addTests(b, "uplink-tests-evented", true, test_inputs);
    // `uplink.wire`'s own tests, built as its root: a module's tests run only
    // from the build that has it as the root, and this build has aegis and
    // shakedown to import and nothing of the client.
    const wire_tests = b.addTest(.{
        .name = "uplink-wire-tests",
        .filters = if (test_filter) |filter| &.{filter} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = p.path("src/wire_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "aegis", .module = aegis }},
        }),
    });
    wire_tests.root_module.addImport("shakedown", shakedown.module("shakedown"));

    const test_step = b.step("test", "Run the tests and the example");
    const tests_run = b.addRunArtifact(tests);
    const wire_run = b.addRunArtifact(wire_tests);
    const evented_run = b.addRunArtifact(evented_tests);
    evented_run.step.dependOn(&tests_run.step);
    wire_run.step.dependOn(&evented_run.step);
    test_step.dependOn(&tests_run.step);
    test_step.dependOn(&wire_run.step);
    test_step.dependOn(&evented_run.step);

    const check_step = b.step("check", "Compile the tests and the example without running them");
    check_step.dependOn(&tests.step);
    check_step.dependOn(&wire_tests.step);
    check_step.dependOn(&evented_tests.step);

    //=====================================================================
    // Example: built AND run against the module a consumer gets.
    // examples/usage.zig is also README.md's Usage block (bay docs --
    // usage), so the snippet a reader copies is code CI executes.
    //=====================================================================

    const example = b.addExecutable(.{
        .name = "usage",
        .root_module = b.createModule(.{
            .root_source_file = p.path("examples/usage.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "uplink", .module = module },
                .{ .name = "reactor", .module = reactor },
                .{ .name = "cloak", .module = cloak },
            },
        }),
    });
    const example_run = b.addRunArtifact(example);
    example_run.setCwd(p.path("."));
    const examples_step = b.step("examples", "Build and run the usage example");
    examples_step.dependOn(&example_run.step);
    test_step.dependOn(examples_step);
    check_step.dependOn(&example.step);

    b.getInstallStep().dependOn(check_step);

    //=====================================================================
    // CI wiring.
    //=====================================================================

    preflight.addCi(b, p, .{
        .tests = test_step,
        .portable_tests = true,
        // uplink's own measurements, in bench/: `bay bench` builds
        // them in ReleaseFast and runs them, and `bay test` runs
        // each once with `--smoke`.
        .bench = .{
            .programs = &.{.{ .name = "uplink-bench", .source = "bench/main.zig" }},
            .imports = benchImports,
            .target = target,
            .optimize = optimize,
        },
    });
    // A project that depends on uplink by path, with only aegis,
    // reactor and cloak to fetch: the build a client's user gets.
    preflight.addConsumerCheck(b, p, .{ .package = "uplink", .program = p.path("ci/consumer.zig"), .modules = &.{ "uplink", "uplink.wire" }, .packages = &.{ aegis_package, reactor_package, cloak_package } });
    addWireConsumerCheck(b, p, aegis_package);
    addColdConsumerCheck(b, p);
}

/// uplink in the mode a benchmark builds in: an imported module keeps its
/// own mode, so a ReleaseFast benchmark over the Debug module would time
/// the Debug module. And shakedown.
fn benchImports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) []const std.Build.Module.Import {
    const package = b.dependency("uplink", .{ .target = target, .optimize = optimize });
    const p = package.builder;
    const reactor = p.dependency("reactor", .{ .target = target, .optimize = optimize }).module("reactor");
    const cloak = p.dependency("cloak", .{ .target = target, .optimize = optimize }).module("cloak");
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "uplink", .module = package.module("uplink") },
        .{ .name = "reactor", .module = reactor },
        .{ .name = "cloak", .module = cloak },
    }) catch @panic("OOM");
}

/// What the build publishes: the codecs, and with a client, everything.
const Modules = struct {
    /// `uplink.wire`: the codecs, sans I/O, on `std` and aegis alone.
    wire: *std.Build.Module,
    /// `uplink`, which names every concern; absent in a build without the client.
    root: ?*std.Build.Module,
};

/// The modules, one set of source files per module: `uplink` imports `uplink.wire`
/// rather than its files, so a type is one declaration whichever a user names.
fn uplinkModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, aegis: *std.Build.Module, client: bool, reactor: ?*std.Build.Module, cloak: ?*std.Build.Module) Modules {
    const wire_options: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("src/wire.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "aegis", .module = aegis }},
    };
    const wire = b.addModule("uplink.wire", wire_options);
    if (!client) return .{ .wire = wire, .root = null };
    // Declared before reactor and cloak are fetched: a consumer's first pass
    // must find the module it asks for, and only learns here what to fetch.
    // They are imported once they are there.
    const root_options: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("src/uplink.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "aegis", .module = aegis },
            .{ .name = "uplink.wire", .module = wire },
        },
    };
    const root = b.addModule("uplink", root_options);
    if (reactor) |module| root.addImport("reactor", module);
    if (cloak) |module| root.addImport("cloak", module);
    return .{ .wire = wire, .root = root };
}

/// What both builds of the test suite are made from.
const TestInputs = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    imports: []const std.Build.Module.Import,
    shakedown: *std.Build.Module,
    /// uplink's own build, which holds its files.
    package: *std.Build,
    filter: ?[]const u8,
};

/// The test suite, running on `std.testing.io` or, `evented`, on a reactor
/// runtime (`src/testing/io.zig` says which it was built for).
fn addTests(b: *std.Build, name: []const u8, evented: bool, inputs: TestInputs) *std.Build.Step.Compile {
    const tests = b.addTest(.{
        .name = name,
        .filters = if (inputs.filter) |filter| &.{filter} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = inputs.package.path("src/tests.zig"),
            .target = inputs.target,
            .optimize = inputs.optimize,
            .imports = inputs.imports,
        }),
    });
    tests.root_module.addImport("shakedown", inputs.shakedown);
    const io = b.addOptions();
    io.addOption(bool, "evented", evented);
    tests.root_module.addOptions("test_io", io);
    return tests;
}

/// `check-wire-consumer`: a project that asks for `uplink.wire` alone
/// (`.client = false`), built with fetching off and only aegis in its package
/// directory. reactor, shakedown and preflight are absent, so the build fails
/// if `uplink.wire` or the build script reaches for any of them.
fn addWireConsumerCheck(b: *std.Build, p: *std.Build, aegis: *std.Build.Dependency) void {
    const generator = b.addExecutable(.{ .name = "wire-consumer", .root_module = b.createModule(.{
        .root_source_file = p.path("ci/wire_consumer.zig"),
        .target = b.graph.host,
        .optimize = .debug,
    }) });
    const packages = b.addWriteFiles();
    _ = packages.add("README", "aegis, and nothing else.\n");
    _ = packages.addCopyDirectory(aegis.path(""), aegis.builder.pkg_hash, .{});
    const run = b.addRunArtifact(generator);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg2(b.graph.path(.local_cache, "uplink-wire-consumer"), .{});
    run.addDirectoryArg2(packages.getDirectory(), .{});
    run.addDirectoryArg2(p.path("."), .{});
    run.addFileArg(p.path("ci/wire_program.zig"));
    run.has_side_effects = true;
    b.step("check-wire-consumer", "Build a project that asks for uplink.wire alone, with only aegis to fetch").dependOn(&run.step);
}

/// `check-cold-consumer`: a project that depends on uplink as a client, built
/// from an empty package cache. The first pass of its build has no reactor or cloak,
/// so uplink's script must declare `uplink` before it asks for reactor, then
/// configure once the package is fetched.
fn addColdConsumerCheck(b: *std.Build, p: *std.Build) void {
    const generator = b.addExecutable(.{ .name = "cold-consumer", .root_module = b.createModule(.{
        .root_source_file = p.path("ci/wire_consumer.zig"),
        .target = b.graph.host,
        .optimize = .debug,
    }) });
    const run = b.addRunArtifact(generator);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg2(b.graph.path(.local_cache, "uplink-cold-consumer"), .{});
    run.addDirectoryArg2(p.path("."), .{});
    run.addDirectoryArg2(p.path("."), .{});
    run.addFileArg(p.path("ci/cold_program.zig"));
    run.addArg("cold");
    run.has_side_effects = true;
    b.step("check-cold-consumer", "Build a client project from an empty package cache").dependOn(&run.step);
}
