//! The TLS client held to the standard library's.
//!
//! `tls/Client.zig` is std's `Client.zig` with client authentication added,
//! and `tls/Client.zig.diff` is the whole of what was added. Two things can
//! make that untrue, and each fails here:
//!
//! - std's file changes under us — a Zig release with a fix in its client —
//!   and the copy goes on without the fix. The diff's first line names the
//!   SHA-256 of the std file it was taken against, and the std file this
//!   compiler ships is hashed and compared.
//! - the copy is changed and the diff is not, so the diff no longer says
//!   what the copy is. The diff is applied to std's file and the result
//!   compared with the copy, byte for byte.
//!
//! `zig build tls-fork` takes the diff again; the header of `tls/Client.zig`
//! says what to do when this fails.

const std = @import("std");
const std_tls_client = @import("std_tls_client");

const fork = @embedFile("../tls/Client.zig");
const recorded = @embedFile("../tls/Client.zig.diff");

test "the TLS client is std's, with the recorded diff and nothing else" {
    const gpa = std.testing.allocator;
    const std_client = std_tls_client.source;

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std_client, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    const expected = baseHash(recorded) orelse return error.TestUnexpectedResult;
    if (!std.mem.eql(u8, &actual, expected)) {
        std.debug.print(
            \\std's TLS client is not the one s../tls/Client.zig was taken from:
            \\  {s}
            \\  sha256 {s}, recorded {s}
            \\Bring std's changes across as the header of s../tls/Client.zig says,
            \\then run zig build tls-fork.
            \\
        , .{ "std/crypto/tls/Client.zig", &actual, expected });
        return error.TestUnexpectedResult;
    }

    const applied = try apply(gpa, std_client, recorded);
    defer gpa.free(applied);
    try std.testing.expectEqualStrings(fork, applied);
}

/// The hex SHA-256 in the diff's `---` line: `... sha256:<hex>`.
fn baseHash(diff: []const u8) ?[]const u8 {
    const first = diff[0 .. std.mem.findScalar(u8, diff, '\n') orelse return null];
    if (!std.mem.startsWith(u8, first, "--- ")) return null;
    const at = std.mem.findLast(u8, first, "sha256:") orelse return null;
    const hex = first[at + "sha256:".len ..];
    return if (hex.len == 64) hex else null;
}

/// `original` with the unified diff `diff` applied: every context and
/// removed line checked against `original`, every added line put in. A line
/// that does not match is `error.DiffDoesNotApply`, which is the copy and
/// the diff disagreeing.
fn apply(gpa: std.mem.Allocator, original: []const u8, diff: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var source = std.mem.splitScalar(u8, original, '\n');
    var line_no: usize = 1; // the number of the line `source` gives next

    var hunks = std.mem.splitScalar(u8, diff, '\n');
    // The two header lines.
    _ = hunks.next() orelse return error.DiffDoesNotApply;
    _ = hunks.next() orelse return error.DiffDoesNotApply;
    while (hunks.next()) |line| {
        if (line.len == 0) continue; // the end of the diff
        if (std.mem.startsWith(u8, line, "@@ -")) {
            const rest = line["@@ -".len..];
            const end = std.mem.findAny(u8, rest, ", ") orelse return error.DiffDoesNotApply;
            const start = try std.fmt.parseInt(usize, rest[0..end], 10);
            // Everything before the hunk is the original's, as it is.
            while (line_no < start) : (line_no += 1) {
                try out.appendSlice(gpa, source.next() orelse return error.DiffDoesNotApply);
                try out.append(gpa, '\n');
            }
            continue;
        }
        switch (line[0]) {
            ' ', '-' => {
                const had = source.next() orelse return error.DiffDoesNotApply;
                if (!std.mem.eql(u8, had, line[1..])) return error.DiffDoesNotApply;
                line_no += 1;
                if (line[0] == ' ') {
                    try out.appendSlice(gpa, had);
                    try out.append(gpa, '\n');
                }
            },
            '+' => {
                try out.appendSlice(gpa, line[1..]);
                try out.append(gpa, '\n');
            },
            '\\' => {}, // "No newline at end of file"; neither file lacks one
            else => return error.DiffDoesNotApply,
        }
    }
    // The rest of the original. Its final element is what follows the last
    // newline, which is nothing.
    while (source.next()) |rest| {
        try out.appendSlice(gpa, rest);
        if (source.peek() != null) try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

test apply {
    const gpa = std.testing.allocator;
    const original = "a\nb\nc\nd\ne\n";
    const diff =
        \\--- x sha256:0000
        \\+++ y
        \\@@ -2,3 +2,3 @@
        \\ b
        \\-c
        \\+C
        \\ d
        \\
    ;
    const applied = try apply(gpa, original, diff);
    defer gpa.free(applied);
    try std.testing.expectEqualStrings("a\nb\nC\nd\ne\n", applied);

    const wrong =
        \\--- x
        \\+++ y
        \\@@ -2,1 +2,1 @@
        \\-z
        \\+Z
        \\
    ;
    try std.testing.expectError(error.DiffDoesNotApply, apply(gpa, original, wrong));
}
