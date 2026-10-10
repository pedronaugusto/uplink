//! Writes the project `zig build check-wire-consumer` builds and builds it:
//! a consumer of `uplink.wire` alone. The build runs this file as a program:
//! `<zig> <project> <packages> <uplink root> <program>`.
//!
//! The project depends on uplink by path with `.client = false`, fetching is
//! off, and the package directory holds aegis and nothing else. A build that
//! reached for reactor, which only the client needs, would fail to find it.
//! The build has a Zig cache of its own, so no package found in the global
//! cache stands in for one the project failed to ask for.
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 6) return error.MissingArguments;
    const cwd = std.Io.Dir.cwd();
    var dir = try cwd.createDirPathOpen(io, args[2], .{});
    defer dir.close(io);
    try dir.createDirPath(io, "src");
    const directory = try cwd.realPathFileAlloc(io, args[2], a);
    const root = try cwd.realPathFileAlloc(io, args[4], a);
    const relative = try std.Io.Dir.path.relativeAlloc(a, directory, null, directory, root);
    std.mem.replaceScalar(u8, relative, '\\', '/');
    const program = try cwd.readFileAlloc(io, args[5], a, .limited(1024 * 1024));
    try dir.writeFile(io, .{ .sub_path = "src/main.zig", .data = program });
    try dir.writeFile(io, .{ .sub_path = "build.zig.zon", .data = try a.print(manifest, .{std.zig.fmtString(relative)}) });
    try dir.writeFile(io, .{ .sub_path = "build.zig", .data = script });
    var env = try init.environ_map.clone(a);
    try env.put("ZIG_GLOBAL_CACHE_DIR", try std.Io.Dir.path.join(a, &.{ directory, ".zig-global-cache" }));
    const packages = try cwd.realPathFileAlloc(io, args[3], a);
    var child = try std.process.spawn(io, .{ .argv = &.{ args[1], "build", "--system", packages }, .cwd = .{ .path = directory }, .environ_map = &env });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) std.process.exit(1);
}

const manifest =
    \\.{{
    \\    .name = .consumer,
    \\    .version = "0.0.0",
    \\    .fingerprint = 0x705b37272f017aed,
    \\    .minimum_zig_version = "0.17.0",
    \\    .dependencies = .{{ .uplink = .{{ .path = "{f}" }} }},
    \\    .paths = .{{""}},
    \\}}
    \\
;

const script =
    \\const std = @import("std");
    \\pub fn build(b: *std.Build) void {
    \\    const target = b.standardTargetOptions(.{});
    \\    const optimize = b.standardOptimizeOption(.{});
    \\    const uplink = b.dependency("uplink", .{ .target = target, .optimize = optimize, .client = false });
    \\    const exe = b.addExecutable(.{ .name = "consumer", .root_module = b.createModule(.{
    \\        .root_source_file = b.path("src/main.zig"),
    \\        .target = target,
    \\        .optimize = optimize,
    \\        .imports = &.{.{ .name = "uplink.wire", .module = uplink.module("uplink.wire") }},
    \\    }) });
    \\    b.installArtifact(exe);
    \\}
    \\
;
