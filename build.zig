const std = @import("std");

/// What a project that depends on uplink is given: `uplink.wire`, the codecs, and `uplink`,
/// the client over them. No option: a program compiles the module it imports.
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
    // reactor, cloak, warp (the codings), xenoglyph (domain names) and
    // airlock (the disk cache's durable files) are lazy dependencies: fetched
    // with uplink, and compiled only in a program that imports `uplink`. A
    // program that imports `uplink.wire` alone compiles std and aegis.
    //=====================================================================

    const aegis = b.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis");
    // Every lazy dependency asked for before any is used, so one configure pass marks them all.
    const reactor: ?*std.Build.Module = if (b.dependencyLazy("reactor", .{ .target = target, .optimize = optimize })) |package| package.module("reactor") else |_| null;
    const cloak: ?*std.Build.Module = if (b.dependencyLazy("cloak", .{ .target = target, .optimize = optimize })) |package| package.module("cloak") else |_| null;
    const warp: ?*std.Build.Module = if (b.dependencyLazy("warp", .{ .target = target, .optimize = optimize })) |package| package.module("warp") else |_| null;
    const xenoglyph: ?*std.Build.Module = if (b.dependencyLazy("xenoglyph", .{ .target = target, .optimize = optimize })) |package| package.module("xenoglyph") else |_| null;
    const airlock: ?*std.Build.Module = if (b.dependencyLazy("airlock", .{ .target = target, .optimize = optimize })) |package| package.module("airlock") else |_| null;
    _ = uplinkModules(b, target, optimize, aegis, .{ .reactor = reactor, .cloak = cloak, .warp = warp, .xenoglyph = xenoglyph, .airlock = airlock });
}

/// The lazy dependency `name` of `p`, or null where it is not fetched yet: std has marked it
/// needed, and the build fetches it and configures again, so this pass makes nothing of it.
fn fetched(p: *std.Build, name: []const u8, args: anytype) ?*std.Build.Dependency {
    return p.dependencyLazy(name, args) catch |err| switch (err) {
        error.LazyDependencyNeeded => null,
    };
}

/// uplink's development: its tests, example, checks and benchmarks, under
/// preflight's gate. Run through bay.
pub fn dev(b: *std.Build, tools: type) void {
    // std's lazyImport compares every package of the tree at comptime: the tree passes the
    // default branch quota (preflight's lazy-import check).
    @setEvalBranchQuota(10_000);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const preflight = tools.preflight;
    const package = b.dependency("uplink", .{ .target = target, .optimize = optimize });
    const p = package.builder;
    const aegis_package = p.dependency("aegis", .{ .target = target, .optimize = optimize });
    const aegis = aegis_package.module("aegis");
    // reactor, cloak, warp, xenoglyph and airlock are lazy: one not fetched yet ends this configure
    // pass (`fetched`).
    const reactor_package = fetched(p, "reactor", .{ .target = target, .optimize = optimize }) orelse return;
    const cloak_package = fetched(p, "cloak", .{ .target = target, .optimize = optimize }) orelse return;
    const warp_package = fetched(p, "warp", .{ .target = target, .optimize = optimize }) orelse return;
    const xenoglyph_package = fetched(p, "xenoglyph", .{ .target = target, .optimize = optimize }) orelse return;
    const airlock_package = fetched(p, "airlock", .{ .target = target, .optimize = optimize }) orelse return;
    const reactor = reactor_package.module("reactor");
    const cloak = cloak_package.module("cloak");
    const warp = warp_package.module("warp");
    const xenoglyph = xenoglyph_package.module("xenoglyph");
    const airlock = airlock_package.module("airlock");
    const shakedown = b.dependency("shakedown", .{ .target = target, .optimize = optimize });
    // reactor's seam for the simulated network's tests: an `Io` whose sockets are not the
    // system's, where reactor's raw socket calls ask the test instead.
    const reactor_build = b.lazyImport(@This(), "reactor") orelse return;
    const reactor_testing = reactor_build.testing(reactor_package, shakedown.module("shakedown"));

    const module = package.module("uplink");
    const wire = package.module("uplink.wire");
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "aegis", .module = aegis },
        .{ .name = "reactor", .module = reactor },
        .{ .name = "cloak", .module = cloak },
        .{ .name = "warp", .module = warp },
        .{ .name = "xenoglyph", .module = xenoglyph },
        .{ .name = "airlock", .module = airlock },
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
        .reactor_testing = reactor_testing,
        .package = p,
        .filter = test_filter,
    };
    // The suite runs on `Io.Threaded`, which `std.testing.io` is, and on a
    // reactor runtime, the evented `Io` uplink is built for, once on each
    // kernel backend the target has, a test binary for each (a run's
    // environment would stay in Zig's cached configuration). One after the
    // other, so no run loads the machine another's timers run on.
    const tests = addTests(b, "uplink-tests", null, test_inputs);
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
    wire_tests.root_module.addImport("json_schema", jsonSchema(b, p));

    const test_step = b.step("test", "Run the tests and the example");
    const tests_run = b.addRunArtifact(tests);
    const wire_run = b.addRunArtifact(wire_tests);
    test_step.dependOn(&tests_run.step);
    const check_step = b.step("check", "Compile the tests and the example without running them");
    check_step.dependOn(&tests.step);
    check_step.dependOn(&wire_tests.step);
    var previous = &tests_run.step;
    for (backends(target.result.os.tag)) |backend| {
        const evented_tests = addTests(b, b.fmt("uplink-tests-{s}", .{backend}), backend, test_inputs);
        check_step.dependOn(&evented_tests.step);
        const evented_run = b.addRunArtifact(evented_tests);
        evented_run.step.dependOn(previous);
        test_step.dependOn(&evented_run.step);
        previous = &evented_run.step;
    }
    wire_run.step.dependOn(previous);
    test_step.dependOn(&wire_run.step);

    // The codecs alone, and the suite on `Io.Threaded` alone: the release
    // tier fuzzes the codecs' properties and runs the threaded suite under
    // ThreadSanitizer.
    b.step("wire", "Run uplink.wire's tests alone").dependOn(&b.addRunArtifact(wire_tests).step);
    b.step("unit", "Run the suite on Io.Threaded alone").dependOn(&b.addRunArtifact(tests).step);

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

    // Conformance: the protocols' own suites, driven by Zig programs that
    // run the peers installed on the machine and read their reports. By
    // hand, before a cut: CI compiles them only.
    const conformance = [_]struct { name: []const u8, about: []const u8 }{
        .{ .name = "autobahn", .about = "Autobahn|Testsuite against the WebSocket client or server: -- server|client <wstest> <workdir>" },
        .{ .name = "h2spec", .about = "h2spec against the HTTP/2 server: -- <h2spec> <workdir> [--tls <cert.pem> <key.pem>] [h2spec's options]" },
        .{ .name = "h1", .about = "An HTTP/1.1 conformance tool against the server: -- <command> [arguments, {url} and {port} replaced]" },
    };
    for (conformance) |c| {
        const exe = b.addExecutable(.{
            .name = c.name,
            .root_module = b.createModule(.{
                .root_source_file = p.path(b.fmt("conformance/{s}.zig", .{c.name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "uplink", .module = module },
                    .{ .name = "reactor", .module = reactor },
                    .{ .name = "cloak", .module = cloak },
                    .{ .name = "aegis", .module = aegis },
                },
            }),
        });
        const run = b.addRunArtifact(exe);
        run.addPassthruArgs();
        b.step(c.name, c.about).dependOn(&run.step);
        check_step.dependOn(&exe.step);
    }

    b.getInstallStep().dependOn(check_step);

    //=====================================================================
    // CI wiring.
    //=====================================================================

    preflight.addCi(b, p, .{
        .tests = test_step,
        .portable_tests = true,
        .hardened = .{ .fuzz_step = "wire", .tsan_step = "unit" },
        // The TLS interop tests' peer, on the riscv64 machine as on every
        // hosted runner.
        .vm_packages = &.{"openssl"},
        // uplink's own measurements, in bench/: `bay bench` builds
        // them in ReleaseFast and runs them, and `bay test` runs
        // each once with `--smoke`.
        .bench = .{
            .programs = &.{.{ .name = "uplink-bench", .source = "bench/main.zig" }},
            .imports = tools.preflight.Bench.importsFrom(benchImports),
            .target = target,
            .optimize = optimize,
        },
    });
    // A project that depends on uplink by path, with only aegis, reactor,
    // cloak and warp (and what they depend on) to fetch: the build a
    // client's user gets.
    const packages: []const *std.Build.Dependency = &.{ aegis_package, reactor_package, cloak_package, warp_package, xenoglyph_package, airlock_package };
    preflight.addConsumerCheck(b, p, .{ .package = "uplink", .program = p.path("ci/consumer.zig"), .modules = &.{ "uplink", "uplink.wire" }, .packages = packages });
    addWireConsumerCheck(b, p, packages);
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
    const warp = p.dependency("warp", .{ .target = target, .optimize = optimize }).module("warp");
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "uplink", .module = package.module("uplink") },
        .{ .name = "reactor", .module = reactor },
        .{ .name = "cloak", .module = cloak },
        .{ .name = "warp", .module = warp },
    }) catch @panic("OOM");
}

/// What the build publishes: the codecs, and everything.
const Modules = struct {
    /// `uplink.wire`: the codecs, sans I/O, on `std` and aegis alone.
    wire: *std.Build.Module,
    /// `uplink`, which names every concern.
    root: *std.Build.Module,
};

/// The lazy packages `uplink` imports, each null until it is fetched.
const Lazy = struct {
    reactor: ?*std.Build.Module,
    cloak: ?*std.Build.Module,
    warp: ?*std.Build.Module,
    xenoglyph: ?*std.Build.Module,
    airlock: ?*std.Build.Module,
};

/// The modules, one set of source files per module: `uplink` imports `uplink.wire`
/// rather than its files, so a type is one declaration whichever a user names.
fn uplinkModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, aegis: *std.Build.Module, lazy: Lazy) Modules {
    // Each module named and rooted by literals: preflight's release check reads what the
    // package exports from this text.
    const wire = b.addModule("uplink.wire", .{
        .root_source_file = b.path("src/wire.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "aegis", .module = aegis }},
    });
    // Declared before reactor and cloak are fetched: a consumer's first pass
    // must find the module it asks for, and only learns here what to fetch.
    // They are imported once they are there.
    const root = b.addModule("uplink", .{
        .root_source_file = b.path("src/uplink.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "aegis", .module = aegis },
            .{ .name = "uplink.wire", .module = wire },
        },
    });
    if (lazy.reactor) |module| root.addImport("reactor", module);
    if (lazy.cloak) |module| root.addImport("cloak", module);
    if (lazy.warp) |module| root.addImport("warp", module);
    if (lazy.xenoglyph) |module| root.addImport("xenoglyph", module);
    if (lazy.airlock) |module| root.addImport("airlock", module);
    return .{ .wire = wire, .root = root };
}

/// What both builds of the test suite are made from.
const TestInputs = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    imports: []const std.Build.Module.Import,
    shakedown: *std.Build.Module,
    reactor_testing: *std.Build.Module,
    /// uplink's own build, which holds its files.
    package: *std.Build,
    filter: ?[]const u8,
};

/// The test suite, running on `std.testing.io` or, with a `backend`, on a
/// reactor runtime over it (`src/testing/io.zig` says which it was built for).
fn addTests(b: *std.Build, name: []const u8, backend: ?[]const u8, inputs: TestInputs) *std.Build.Step.Compile {
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
    tests.root_module.addImport("reactor.testing", inputs.reactor_testing);
    const io = b.addOptions();
    io.addOption(?[]const u8, "backend", backend);
    tests.root_module.addOptions("test_io", io);
    return tests;
}

/// The reactor backends a target's kernel has, by `Runtime.Backend`'s names:
/// the evented suite runs once on each.
fn backends(os: std.Target.Os.Tag) []const []const u8 {
    return switch (os) {
        .linux => &.{ "io_uring", "epoll" },
        .windows => &.{"iocp"},
        .freebsd, .openbsd, .netbsd, .dragonfly => &.{"kqueue"},
        else => if (os.isDarwin()) &.{"kqueue"} else &.{"auto"},
    };
}

/// `check-wire-consumer`: a project that imports `uplink.wire` alone compiles
/// nothing of the client. It is built with fetching off and every package
/// uplink's graph needs in its package directory, as a fetch leaves them; the
/// program imports `uplink.wire` and nothing else, and builds.
fn addWireConsumerCheck(b: *std.Build, p: *std.Build, dependencies: []const *std.Build.Dependency) void {
    const generator = b.addExecutable(.{ .name = "wire-consumer", .root_module = b.createModule(.{
        .root_source_file = p.path("ci/wire_consumer.zig"),
        .target = b.graph.host,
        .optimize = .debug,
        .imports = &.{.{ .name = "aegis", .module = hostAegis(p) }},
    }) });
    const packages = b.addWriteFiles();
    _ = packages.add("README", "uplink's dependencies, and what they depend on.\n");
    var closure: std.array_hash_map.String(void) = .empty;
    for (dependencies) |dependency| gather(b, &closure, dependency.builder.pkg_hash);
    for (closure.keys()) |hash| {
        if (!fetchedByHash(hash)) continue;
        const entry = std.Build.package_map.get(hash) orelse unreachable; // gather puts only hashes it found
        _ = packages.addCopyDirectory(.{ .cwd_relative = entry.build_root }, hash, .{});
    }
    const run = b.addRunArtifact(generator);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg2(b.graph.path(.local_cache, "uplink-wire-consumer"), .{});
    run.addDirectoryArg2(packages.getDirectory(), .{});
    run.addDirectoryArg2(p.path("."), .{});
    run.addFileArg(p.path("ci/wire_program.zig"));
    run.has_side_effects = true;
    const step = b.step("check-wire-consumer", "Build a project that imports uplink.wire alone, with fetching off");
    step.dependOn(&run.step);
    step.dependOn(&inGraph(b, p, "wire_program", "uplink.wire").step);
}

/// Puts `hash` and every package it depends on, transitively, into `closure`, as
/// preflight's consumer check gathers them: with fetching off, the build needs each on
/// disk. A package reached by path is read where it is, and a lazy one never fetched
/// was asked for by nothing here.
fn gather(b: *std.Build, closure: *std.array_hash_map.String(void), hash: []const u8) void {
    const entry = std.Build.package_map.get(hash) orelse return;
    if (!entry.available) return;
    const found = closure.getOrPut(b.graph.arena, hash) catch @panic("OOM");
    if (found.found_existing) return;
    for (entry.deps) |dependency| gather(b, closure, dependency[1]);
}

/// Whether Zig fetched the package `key` names by hash (`name-version-digest`, the digest
/// 44 characters), which a build with fetching off looks up among its packages. A package
/// reached by path is keyed by its path, or by a digest when the path is long.
fn fetchedByHash(key: []const u8) bool {
    if (key.len < 44 or std.mem.findAny(u8, key, "/\\") != null) return false;
    return std.mem.countScalar(u8, key[0 .. key.len - 44], '-') >= 2;
}

/// aegis for the programs the build runs on the machine it runs on.
fn hostAegis(p: *std.Build) *std.Build.Module {
    return p.dependency("aegis", .{ .target = p.graph.host, .optimize = .debug }).module("aegis");
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
        .imports = &.{.{ .name = "aegis", .module = hostAegis(p) }},
    }) });
    const run = b.addRunArtifact(generator);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg2(b.graph.path(.local_cache, "uplink-cold-consumer"), .{});
    run.addDirectoryArg2(p.path("."), .{});
    run.addDirectoryArg2(p.path("."), .{});
    run.addFileArg(p.path("ci/cold_program.zig"));
    run.addArg("cold");
    run.has_side_effects = true;
    const step = b.step("check-cold-consumer", "Build a client project from an empty package cache");
    step.dependOn(&run.step);
    step.dependOn(&inGraph(b, p, "cold_program", "uplink").step);
}

/// A consumer's program compiled against the package's own module in this build, an object
/// nothing installs, as preflight's `addConsumerCheck` does for `ci/consumer.zig`: lint reads
/// only the configured graph, and the consumer's project is written only when its check runs,
/// so this is what tells lint what the program's import is.
fn inGraph(b: *std.Build, p: *std.Build, comptime program: []const u8, module: []const u8) *std.Build.Step.Compile {
    const root = b.createModule(.{ .root_source_file = p.path("ci/" ++ program ++ ".zig"), .target = b.graph.host, .optimize = .debug });
    root.addImport(module, p.modules.get(module).?);
    return b.addObject(.{ .name = program, .root_module = root });
}

/// JSON-Schema-Test-Suite's URI format cases (testdata/json-schema, release 23.2.0, MIT), as a module.
fn jsonSchema(b: *std.Build, p: *std.Build) *std.Build.Module {
    const files = b.addWriteFiles();
    var source: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "uri", "uri-reference", "iri", "iri-reference" }) |name| {
        _ = files.addCopyFile(p.path(b.fmt("testdata/json-schema/{s}.json", .{name})), b.fmt("{s}.json", .{name}));
        source.print(b.allocator, "pub const @\"{s}\" = @embedFile(\"{s}.json\");\n", .{ name, name }) catch @panic("OOM");
    }
    _ = files.addCopyFile(p.path("testdata/json-schema/version"), "version");
    source.appendSlice(b.allocator, "pub const version = @embedFile(\"version\");\n") catch @panic("OOM");
    return b.createModule(.{ .root_source_file = files.add("json_schema.zig", source.items) });
}
