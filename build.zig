const std = @import("std");

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

    const own_tree = b.dep_prefix.len == 0;
    const with_client = own_tree or (b.option(bool, "client", "Build the HTTP client and the `uplink` module, which fetch reactor; false leaves `uplink.wire` alone") orelse true);
    const aegis_package = b.dependency("aegis", .{ .target = target, .optimize = optimize });
    const aegis = aegis_package.module("aegis");
    const reactor_package: ?*std.Build.Dependency = if (with_client) b.dependencyLazy("reactor", .{ .target = target, .optimize = optimize }) catch null else null;
    const reactor: ?*std.Build.Module = if (reactor_package) |package| package.module("reactor") else null;
    const cloak_package: ?*std.Build.Dependency = if (with_client) b.dependencyLazy("cloak", .{ .target = target, .optimize = optimize }) catch null else null;
    const cloak: ?*std.Build.Module = if (cloak_package) |package| package.module("cloak") else null;

    // The tests below ask for shakedown and preflight in the same pass, so
    // one fetch gets all three.
    var shakedown: ?*std.Build.Module = null;
    if (own_tree) {
        if (b.dependencyLazy("shakedown", .{ .target = target, .optimize = optimize }) catch null) |dep| shakedown = dep.module("shakedown");
    }

    const modules = uplinkModules(b, target, optimize, aegis, with_client, reactor, cloak, true);
    // reactor and cloak are not fetched yet: this pass only found out what to fetch.
    if (with_client and (reactor == null or cloak == null)) return;
    // Everything below is uplink's own: a project depending on uplink
    // neither needs nor fetches shakedown or preflight.
    if (!own_tree) return;
    const module = modules.root.?;
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "aegis", .module = aegis },
        .{ .name = "reactor", .module = reactor.? },
        .{ .name = "cloak", .module = cloak.? },
        .{ .name = "uplink.wire", .module = modules.wire },
    };

    //=====================================================================
    // Tests. shakedown is a lazy, test-only dependency: production uplink
    // imports aegis alone.
    //=====================================================================

    const test_filter = b.option([]const u8, "test-filter", "Select tests by name");
    const test_inputs: TestInputs = .{
        .target = target,
        .optimize = optimize,
        .imports = imports,
        .shakedown = shakedown,
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
            .root_source_file = b.path("src/wire_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "aegis", .module = aegis }},
        }),
    });
    if (shakedown) |shakedown_module| wire_tests.root_module.addImport("shakedown", shakedown_module);

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
                .{ .name = "reactor", .module = reactor.? },
                .{ .name = "cloak", .module = cloak.? },
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
        // A project that depends on uplink by path, with only aegis,
        // reactor and cloak to fetch: the build a client's user gets.
        preflight.addConsumerCheck(b, .{ .package = "uplink", .program = b.path("ci/consumer.zig"), .modules = &.{ "uplink", "uplink.wire" }, .packages = &.{ aegis_package, reactor_package.?, cloak_package.? } });
    }
    addWireConsumerCheck(b, aegis_package);
    addColdConsumerCheck(b);
}

/// uplink in the mode a benchmark builds in: an imported module keeps its
/// own mode, so a ReleaseFast benchmark over the Debug module would time
/// the Debug module.
fn benchImports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) []const std.Build.Module.Import {
    const aegis = b.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis");
    const reactor = b.dependency("reactor", .{ .target = target, .optimize = optimize }).module("reactor");
    const cloak = b.dependency("cloak", .{ .target = target, .optimize = optimize }).module("cloak");
    const uplink = uplinkModules(b, target, optimize, aegis, true, reactor, cloak, false).root.?;
    // Select uplink's published measuring pin rather than preflight's default.
    const shakedown = b.dependency("shakedown", .{ .target = target, .optimize = optimize });
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "uplink", .module = uplink },
        .{ .name = "reactor", .module = reactor },
        .{ .name = "cloak", .module = cloak },
        .{ .name = "shakedown", .module = shakedown.module("shakedown") },
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
/// `publish` names them for consumers; a benchmark builds its own copies, in
/// its own mode.
fn uplinkModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, aegis: *std.Build.Module, client: bool, reactor: ?*std.Build.Module, cloak: ?*std.Build.Module, publish: bool) Modules {
    const wire_options: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("src/wire.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "aegis", .module = aegis }},
    };
    const wire = if (publish) b.addModule("uplink.wire", wire_options) else b.createModule(wire_options);
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
    const root = if (publish) b.addModule("uplink", root_options) else b.createModule(root_options);
    if (reactor) |module| root.addImport("reactor", module);
    if (cloak) |module| root.addImport("cloak", module);
    return .{ .wire = wire, .root = root };
}

/// What both builds of the test suite are made from.
const TestInputs = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    imports: []const std.Build.Module.Import,
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
    if (inputs.shakedown) |module| tests.root_module.addImport("shakedown", module);
    const io = b.addOptions();
    io.addOption(bool, "evented", evented);
    tests.root_module.addOptions("test_io", io);
    return tests;
}

/// `check-wire-consumer`: a project that asks for `uplink.wire` alone
/// (`.client = false`), built with fetching off and only aegis in its package
/// directory. reactor, shakedown and preflight are absent, so the build fails
/// if `uplink.wire` or the build script reaches for any of them.
fn addWireConsumerCheck(b: *std.Build, aegis: *std.Build.Dependency) void {
    const generator = b.addExecutable(.{ .name = "wire-consumer", .root_module = b.createModule(.{
        .root_source_file = b.path("ci/wire_consumer.zig"),
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
    run.addDirectoryArg2(b.path("."), .{});
    run.addFileArg(b.path("ci/wire_program.zig"));
    run.has_side_effects = true;
    b.step("check-wire-consumer", "Build a project that asks for uplink.wire alone, with only aegis to fetch").dependOn(&run.step);
}

/// `check-cold-consumer`: a project that depends on uplink as a client, built
/// from an empty package cache. The first pass of its build has no reactor or cloak,
/// so uplink's script must declare `uplink` before it asks for reactor, then
/// configure once the package is fetched.
fn addColdConsumerCheck(b: *std.Build) void {
    const generator = b.addExecutable(.{ .name = "cold-consumer", .root_module = b.createModule(.{
        .root_source_file = b.path("ci/wire_consumer.zig"),
        .target = b.graph.host,
        .optimize = .debug,
    }) });
    const run = b.addRunArtifact(generator);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg2(b.graph.path(.local_cache, "uplink-cold-consumer"), .{});
    run.addDirectoryArg2(b.path("."), .{});
    run.addDirectoryArg2(b.path("."), .{});
    run.addFileArg(b.path("ci/cold_program.zig"));
    run.addArg("cold");
    run.has_side_effects = true;
    b.step("check-cold-consumer", "Build a client project from an empty package cache").dependOn(&run.step);
}
