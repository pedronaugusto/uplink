//! `wire.h1`'s response parser against a reference written straight from
//! RFC 9112's grammar: the same bytes get the same answer, whole or
//! incomplete, accepted with the same fields or refused.

const std = @import("std");
const testing = std.testing;
const h1 = @import("h1.zig");
const fields = @import("fields.zig");
const reference = @import("../testing/reference_h1.zig");

/// `text` with every run of spaces and tabs made one space, as a folded
/// value reads once a recipient has joined it.
fn collapsed(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var space = false;
    for (text) |c| {
        if (c == ' ' or c == '\t') {
            space = true;
            continue;
        }
        if (space and out.items.len != 0) try out.append(arena, ' ');
        space = false;
        try out.append(arena, c);
    }
    return out.items;
}

fn agree(input: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ours_bytes = try arena.dupe(u8, input);
    var field_buf: [16]fields.Field = undefined;
    const ours = h1.parseResponse(ours_bytes, &field_buf, .{ .max_head = 4096, .max_fields = 16 });
    const theirs = reference.parse(arena, input, 16);
    if (theirs) |head| {
        const parsed = (ours catch |err| {
            std.debug.print("refused {any} as {t}; the reference accepts it\n", .{ input, err });
            return error.TestUnexpectedResult;
        }) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(head.len, parsed.len);
        try testing.expectEqual(head.status, @backingInt(parsed.head.status));
        try testing.expectEqualStrings(head.reason, parsed.head.reason);
        try testing.expectEqual(head.fields.len, parsed.head.headers.count());
        for (head.fields, parsed.head.headers.fields) |want, got| {
            try testing.expectEqualStrings(want.name, got.name);
            try testing.expectEqualStrings(try collapsed(arena, want.value), try collapsed(arena, got.value));
        }
    } else |err| switch (err) {
        error.OutOfMemory => return err,
        error.Incomplete => {
            const parsed = ours catch |e| {
                std.debug.print("refused {any} as {t}; the reference waits for more\n", .{ input, e });
                return error.TestUnexpectedResult;
            };
            try testing.expectEqual(null, parsed);
        },
        error.Invalid => {
            if (ours) |parsed| {
                std.debug.print("accepted {any} ({any}); the reference refuses it\n", .{ input, parsed != null });
                return error.TestUnexpectedResult;
            } else |_| {}
        },
    }
}

test "the parser agrees with the reference on the heads the tests know" {
    for ([_][]const u8{
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        "HTTP/1.1 200\nA: b\n c\n\td\n\n",
        "HTTP/1.0 404 Not Found\r\nA :b\r\n\r\n",
        "HTTP/1.1 200 OK\r\n folded-first: x\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\nA: b",
        "HTTP/1.1 200 OK\r\nA\x00: b\r\n\r\n",
        "\r\n\r\n",
        "HTTP/1.1 200 OK\r\nA: \r\n\r\n",
    }) |input| try agree(input);
}

test "fuzz: the parser agrees with the reference on any bytes" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            try agree(buf[0..smith.slice(&buf)]);
        }
    }.one, .{ .corpus = &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
        "HTTP/1.1 200\nA: b\n c\n\n",
        "HTTP/1.0 301 Moved\r\nLocation: /x\r\nSet-Cookie: a=b\r\n\r\n",
    } });
}

test "the parser agrees with the reference on heads made from HTTP's own pieces" {
    // Random heads built from the bytes and pieces that matter to the
    // grammar, so most inputs get past the status line.
    const pieces = [_][]const u8{
        "HTTP/1.1 200 OK", "HTTP/1.0 404", "HTTP/2.0 200 X", "HTTP/1.1 20",    " ", "\t",   "\r\n", "\n",
        "\r",              ":",            "A",              "Content-Length", "5", "\x00", "\x7f", "\xff",
        "x-y",             "a b",          "chunked",        ",",
    };
    var prng: std.Random.DefaultPrng = .init(testing.random_seed);
    const random = prng.random();
    var buf: [256]u8 = undefined;
    for (0..20_000) |_| {
        var len: usize = 0;
        if (random.boolean()) {
            const start = "HTTP/1.1 200 OK\r\n";
            @memcpy(buf[0..start.len], start);
            len = start.len;
        }
        const count = random.uintLessThan(usize, 24);
        for (0..count) |_| {
            const piece = pieces[random.uintLessThan(usize, pieces.len)];
            if (len + piece.len > buf.len) break;
            @memcpy(buf[len..][0..piece.len], piece);
            len += piece.len;
        }
        if (random.boolean() and len + 4 <= buf.len) {
            @memcpy(buf[len..][0..4], "\r\n\r\n");
            len += 4;
        }
        try agree(buf[0..len]);
    }
}
