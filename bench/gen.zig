//! The benchmarks' corpus, made from a seed so every run measures the same
//! bytes: response heads shaped like real ones, five to forty fields,
//! cookie-heavy, with long values among them.

const std = @import("std");

const names = [_][]const u8{
    "Content-Type",                "Content-Language",        "Cache-Control",             "Date",         "Server", "Vary",
    "ETag",                        "Last-Modified",           "Strict-Transport-Security", "X-Request-Id", "Via",    "Age",
    "Access-Control-Allow-Origin", "Content-Security-Policy", "X-Content-Type-Options",    "Expires",      "Link",   "Alt-Svc",
};

/// `count` response heads, one after another, into `out`.
pub fn heads(gpa: std.mem.Allocator, seed: u64, count: usize) ![]u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    for (0..count) |_| {
        try w.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n", .{random.uintLessThan(u32, 1 << 20)});
        const fields = 5 + random.uintLessThan(usize, 36);
        for (0..fields) |f| {
            if (f % 4 == 3) {
                try w.writeAll("Set-Cookie: ");
                try value(w, random, 40 + random.uintLessThan(usize, 120));
                try w.writeAll("; Path=/; Secure; HttpOnly\r\n");
                continue;
            }
            try w.print("{s}: ", .{names[random.uintLessThan(usize, names.len)]});
            try value(w, random, 8 + random.uintLessThan(usize, if (random.uintLessThan(u8, 8) == 0) 400 else 40));
            try w.writeAll("\r\n");
        }
        try w.writeAll("\r\n");
    }
    return out.toOwnedSlice();
}

fn value(w: *std.Io.Writer, random: std.Random, len: usize) !void {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=.;/ ";
    for (0..len) |i| {
        var c = alphabet[random.uintLessThan(usize, alphabet.len)];
        if (c == ' ' and (i == 0 or i == len - 1)) c = 'x';
        try w.writeByte(c);
    }
}

/// A chunked body of `total` bytes in chunks of `chunk`, with its last
/// chunk, into `gpa`.
pub fn chunked(gpa: std.mem.Allocator, total: usize, chunk: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var left = total;
    while (left > 0) {
        const n = @min(chunk, left);
        try out.writer.print("{x}\r\n", .{n});
        try out.writer.splatByteAll('z', n);
        try out.writer.writeAll("\r\n");
        left -= n;
    }
    try out.writer.writeAll("0\r\n\r\n");
    return out.toOwnedSlice();
}
