//! Re-record the verified std TLS client fork with a labelled unified diff.
const std = @import("std");
const builtin = @import("builtin");
const options = @import("build_options");

fn report(comptime format: []const u8, io: std.Io, args: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stderr().writer(io, &buffer);
    try writer.interface.print(format, args);
    try writer.interface.flush();
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const original = try std.Io.Dir.cwd().readFileAlloc(init.io, options.std_tls_client, a, .limited(8 * 1024 * 1024));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(original, &digest, .{});
    var env = try init.environ_map.clone(a);
    defer env.deinit();
    try env.put("GIT_CONFIG_NOSYSTEM", "1");
    try env.put("GIT_CONFIG_GLOBAL", if (builtin.target.os.tag == .windows) "NUL" else "/dev/null");
    const result = try std.process.run(a, init.io, .{ .environ_map = &env, .argv = &.{ "git", "-c", "diff.noprefix=false", "diff", "--no-index", "--no-ext-diff", "--no-color", "--no-indent-heuristic", "--unified=3", options.std_tls_client, "src/tls/Client.zig" } });
    if (result.term != .exited or result.term.exited > 1) return error.DiffFailed;
    const start = std.mem.find(u8, result.stdout, "\n@@ ") orelse return error.NoForkChanges;
    const patch = try a.print("--- std/crypto/tls/Client.zig zig-{s} sha256:{s}\n+++ src/tls/Client.zig{s}", .{ builtin.zig_version_string, std.fmt.bytesToHex(digest, .lower), result.stdout[start..] });
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "src/tls/Client.zig.diff", .data = patch });
    try report("src/tls/Client.zig.diff: recorded against Zig {s}, sha256 {s}\n", init.io, .{ builtin.zig_version_string, std.fmt.bytesToHex(digest, .lower) });
}
