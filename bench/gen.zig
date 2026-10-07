//! The benchmarks' corpus, made from a seed so every run measures the same
//! bytes: response heads shaped like real ones, five to forty fields,
//! cookie-heavy, with long values among them; chunked bodies; English-like
//! text; Server-Sent Events; `Set-Cookie` values.

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

const words = [_][]const u8{
    "the",        "of",     "and",    "to",     "in",      "a",        "is",     "that",   "for",     "it",
    "as",         "was",    "with",   "be",     "by",      "on",       "not",    "he",     "this",    "are",
    "or",         "his",    "from",   "at",     "which",   "but",      "have",   "an",     "had",     "they",
    "you",        "were",   "their",  "one",    "all",     "we",       "can",    "her",    "has",     "there",
    "been",       "if",     "more",   "when",   "will",    "would",    "who",    "so",     "no",      "she",
    "repository", "commit", "branch", "object", "request", "response", "server", "client", "network", "packet",
};

/// About `len` bytes of English-like text: words in a seeded order, the
/// next often one that followed the last before, as a Markov chain of one
/// word makes it, with sentences and lines.
pub fn text(gpa: std.mem.Allocator, seed: u64, len: usize) ![]u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    var follows: [words.len]usize = undefined;
    for (&follows) |*f| f.* = random.uintLessThan(usize, words.len);
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, len + 64);
    errdefer out.deinit();
    const w = &out.writer;
    var word = random.uintLessThan(usize, words.len);
    var in_sentence: usize = 0;
    while (out.writer.end < len) {
        word = if (random.uintLessThan(u8, 4) != 0) follows[word] else random.uintLessThan(usize, words.len);
        try w.writeAll(words[word]);
        in_sentence += 1;
        if (in_sentence > 6 and random.uintLessThan(u8, 8) == 0) {
            try w.writeAll(if (random.boolean()) ".\n" else ". ");
            in_sentence = 0;
        } else try w.writeByte(' ');
    }
    return out.toOwnedSlice();
}

/// `count` Server-Sent Events, JSON-like, some over several lines, with
/// ids and an event type now and then.
pub fn events(gpa: std.mem.Allocator, seed: u64, count: usize) ![]u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    for (0..count) |i| {
        if (i % 8 == 0) try w.writeAll("event: update\n");
        try w.print("id: {d}\n", .{i});
        const lines = 1 + random.uintLessThan(usize, 3);
        for (0..lines) |_| {
            try w.writeAll("data: {\"key\":\"");
            try token(w, random, 8 + random.uintLessThan(usize, 60));
            try w.writeAll("\"}\n");
        }
        try w.writeAll("\n");
    }
    return out.toOwnedSlice();
}

/// `count` `Set-Cookie` values as servers write them.
pub fn setCookies(gpa: std.mem.Allocator, seed: u64, count: usize) ![][]u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    const list = try gpa.alloc([]u8, count);
    var made: usize = 0;
    errdefer {
        for (list[0..made]) |c| gpa.free(c);
        gpa.free(list);
    }
    for (list) |*c| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        const w = &out.writer;
        try w.print("c{d}=", .{random.int(u16)});
        try token(w, random, 16 + random.uintLessThan(usize, 48));
        try w.writeAll("; Path=/; Domain=.example.com; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax");
        c.* = try out.toOwnedSlice();
        made += 1;
    }
    return list;
}

/// Letters, digits and a few marks: a cookie value or a JSON string.
fn token(w: *std.Io.Writer, random: std.Random, len: usize) !void {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
    for (0..len) |_| try w.writeByte(alphabet[random.uintLessThan(usize, alphabet.len)]);
}
