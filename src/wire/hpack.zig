//! HPACK (RFC 7541): HTTP/2's header compression, both ways. A decoder
//! reads a header block into fields, every name and value copied into the
//! caller's buffer, so a block past it is refused rather than grown (the
//! HPACK bomb); an encoder writes fields, indexing what it may and
//! Huffman-coding a string when that is shorter. The dynamic table is a
//! ring of bytes, each entry contiguous in it, so adding one and evicting
//! the oldest copy nothing but the new entry. Huffman codes are decoded
//! four bits at a time, by a state machine made at compile time from the
//! code table.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const huffman_codes = @import("hpack/huffman_codes.zig").codes;

/// A field as HPACK carries it.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
    /// Never put in a table, here or by an intermediary: a credential.
    never_index: bool = false,
};

/// Why a header block is refused.
pub const Error = error{
    /// Not HPACK: an index past the tables, an integer that overflows, a
    /// string past its block, a broken Huffman code, a table size update
    /// past the limit or after a field.
    Compression,
    /// The fields do not fit the buffer they are copied into.
    HeaderListTooLarge,
    /// More fields than the slice given.
    TooManyFields,
};

const static_table = [_]struct { []const u8, []const u8 }{
    .{ ":authority", "" },                   .{ ":method", "GET" },                  .{ ":method", "POST" },
    .{ ":path", "/" },                       .{ ":path", "/index.html" },            .{ ":scheme", "http" },
    .{ ":scheme", "https" },                 .{ ":status", "200" },                  .{ ":status", "204" },
    .{ ":status", "206" },                   .{ ":status", "304" },                  .{ ":status", "400" },
    .{ ":status", "404" },                   .{ ":status", "500" },                  .{ "accept-charset", "" },
    .{ "accept-encoding", "gzip, deflate" }, .{ "accept-language", "" },             .{ "accept-ranges", "" },
    .{ "accept", "" },                       .{ "access-control-allow-origin", "" }, .{ "age", "" },
    .{ "allow", "" },                        .{ "authorization", "" },               .{ "cache-control", "" },
    .{ "content-disposition", "" },          .{ "content-encoding", "" },            .{ "content-language", "" },
    .{ "content-length", "" },               .{ "content-location", "" },            .{ "content-range", "" },
    .{ "content-type", "" },                 .{ "cookie", "" },                      .{ "date", "" },
    .{ "etag", "" },                         .{ "expect", "" },                      .{ "expires", "" },
    .{ "from", "" },                         .{ "host", "" },                        .{ "if-match", "" },
    .{ "if-modified-since", "" },            .{ "if-none-match", "" },               .{ "if-range", "" },
    .{ "if-unmodified-since", "" },          .{ "last-modified", "" },               .{ "link", "" },
    .{ "location", "" },                     .{ "max-forwards", "" },                .{ "proxy-authenticate", "" },
    .{ "proxy-authorization", "" },          .{ "range", "" },                       .{ "referer", "" },
    .{ "refresh", "" },                      .{ "retry-after", "" },                 .{ "server", "" },
    .{ "set-cookie", "" },                   .{ "strict-transport-security", "" },   .{ "transfer-encoding", "" },
    .{ "user-agent", "" },                   .{ "vary", "" },                        .{ "via", "" },
    .{ "www-authenticate", "" },
};

/// The dynamic table: entries in a ring of bytes, the newest last, each
/// counted as RFC 7541 §4.1 counts it (its name and value and 32).
pub const Table = struct {
    /// Private: the bytes the entries live in, twice the largest size so an
    /// entry that wraps to the start never meets the oldest live one.
    bytes: []u8,
    /// Private: the entries, oldest first from `first`.
    entries: []Entry,
    first: usize = 0,
    count: usize = 0,
    /// Where the next entry's bytes go.
    write: usize = 0,
    /// RFC 7541's size of the entries held, and the most it may be now.
    size: usize = 0,
    max_size: usize,

    pub const Entry = struct { at: u32, name_len: u32, value_len: u32 };

    /// The memory a table of at most `max_size` needs: bytes, and room for
    /// as many entries as can fit.
    pub fn bytesFor(max_size: usize) usize {
        return 2 * max_size;
    }

    pub fn entriesFor(max_size: usize) usize {
        return max_size / 32 + 1;
    }

    pub fn init(bytes: []u8, entries: []Entry, max_size: usize) Table {
        std.debug.assert(bytes.len >= bytesFor(max_size));
        std.debug.assert(entries.len >= entriesFor(max_size));
        return .{ .bytes = bytes, .entries = entries, .max_size = max_size };
    }

    /// Entry `i`, 0 the newest.
    pub fn get(t: *const Table, i: usize) ?struct { []const u8, []const u8 } {
        if (i >= t.count) return null;
        const e = t.entries[(t.first + t.count - 1 - i) % t.entries.len];
        const start: usize = e.at;
        return .{ t.bytes[start..][0..e.name_len], t.bytes[start + e.name_len ..][0..e.value_len] };
    }

    fn evictOldest(t: *Table) void {
        const e = t.entries[t.first];
        t.size -= e.name_len + e.value_len + 32;
        t.first = (t.first + 1) % t.entries.len;
        t.count -= 1;
        if (t.count == 0) t.write = 0;
    }

    /// Change the most the table may hold, evicting what no longer fits.
    pub fn setMaxSize(t: *Table, max_size: usize) void {
        aegis.assert.invariant(t.bytes.len >= bytesFor(max_size), "t.bytes.len >= bytesFor(max_size)");
        t.max_size = max_size;
        while (t.size > t.max_size) t.evictOldest();
    }

    /// Add an entry, evicting the oldest as RFC 7541 §4.4 says; one larger
    /// than the table empties it and is not added.
    pub fn add(t: *Table, name: []const u8, value: []const u8) void {
        const len = name.len + value.len;
        while (t.count != 0 and t.size + len + 32 > t.max_size) t.evictOldest();
        if (len + 32 > t.max_size) return;
        var at = t.write;
        if (at + len > t.bytes.len) at = 0;
        // The oldest entries whose bytes the new one would cover go too.
        while (t.count != 0) {
            const oldest = t.entries[t.first];
            const o_start: usize = oldest.at;
            const o_end = o_start + oldest.name_len + oldest.value_len;
            if (o_end <= at or o_start >= at + len or o_end == o_start) break;
            t.evictOldest();
            if (t.count == 0) at = 0;
        }
        @memcpy(t.bytes[at..][0..name.len], name);
        @memcpy(t.bytes[at + name.len ..][0..value.len], value);
        t.entries[(t.first + t.count) % t.entries.len] = .{ .at = @intCast(at), .name_len = @intCast(name.len), .value_len = @intCast(value.len) };
        t.count += 1;
        t.size += len + 32;
        t.write = at + len;
    }
};

/// Read an integer of an `n`-bit prefix (RFC 7541 §5.1) from `bytes` at
/// `pos.*`.
fn readInt(bytes: []const u8, pos: *usize, comptime n: u4) Error!u64 {
    if (pos.* >= bytes.len) return error.Compression;
    const mask: u8 = (1 << n) - 1;
    var value: u64 = bytes[pos.*] & mask;
    pos.* += 1;
    if (value < mask) return value;
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= bytes.len) return error.Compression;
        const b = bytes[pos.*];
        pos.* += 1;
        if (shift > 56) return error.Compression;
        value += @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return value;
        shift += 7;
    }
}

/// Write `value` with an `n`-bit prefix, `flags` in the bits above it.
fn writeInt(w: *Io.Writer, flags: u8, comptime n: u4, value: u64) Io.Writer.Error!void {
    const mask: u8 = (1 << n) - 1;
    if (value < mask) return w.writeByte(flags | @as(u8, @intCast(value)));
    try w.writeByte(flags | mask);
    var rest = value - mask;
    while (rest >= 0x80) : (rest >>= 7) try w.writeByte(@as(u8, @truncate(rest)) | 0x80);
    try w.writeByte(@intCast(rest));
}

/// The four-bit Huffman decoder: for each state (an inner node of the code
/// tree) and nibble, the state after it, the symbol it ends if one, and
/// whether a string may end there (only on padding of all-ones bits,
/// fewer than eight).
const Step = packed struct(u32) {
    next: u8,
    symbol: u8,
    emits: bool,
    accept: bool,
    fail: bool,
    _: u13 = 0,
};

const decode_table: [256][16]Step = blk: {
    @setEvalBranchQuota(2_000_000);
    // The tree: node 0 the root; children[node][bit], a leaf as 256 + symbol.
    var children: [256][2]u16 = @splat(.{ 0xffff, 0xffff });
    var nodes: usize = 1;
    for (huffman_codes, 0..) |entry, symbol| {
        const code, const len = entry;
        var node: usize = 0;
        var bit: usize = len;
        while (bit > 0) {
            bit -= 1;
            const b = (code >> @intCast(bit)) & 1;
            if (bit == 0) {
                children[node][b] = 256 + symbol;
            } else {
                if (children[node][b] == 0xffff) {
                    children[node][b] = nodes;
                    nodes += 1;
                }
                node = children[node][b];
            }
        }
    }
    // Which nodes are on the all-ones path from the root, and how deep.
    var ones_depth: [256]u8 = @splat(0xff);
    var n: usize = 0;
    var depth: u8 = 0;
    while (true) {
        ones_depth[n] = depth;
        const next = children[n][1];
        if (next >= 256) break;
        n = next;
        depth += 1;
    }
    var table: [256][16]Step = undefined;
    for (0..256) |state| for (0..16) |nibble| {
        var node: usize = state;
        var step: Step = .{ .next = 0, .symbol = 0, .emits = false, .accept = false, .fail = false };
        for (0..4) |i| {
            const b = (nibble >> @intCast(3 - i)) & 1;
            const child = children[node][b];
            if (child == 0xffff) {
                step.fail = true;
                break;
            }
            if (child >= 256) {
                if (child == 256 + 256) {
                    // EOS in a string is an error.
                    step.fail = true;
                    break;
                }
                step.symbol = @intCast(child - 256);
                step.emits = true;
                node = 0;
            } else node = child;
        }
        step.next = @intCast(node);
        step.accept = ones_depth[node] < 8;
        table[state][nibble] = step;
    };
    break :blk table;
};

/// Decode a Huffman-coded string into `out`; the bytes written.
pub fn huffmanDecode(in: []const u8, out: []u8) error{ Compression, HeaderListTooLarge }!usize {
    var state: u8 = 0;
    var accept = true;
    var n: usize = 0;
    for (in) |byte| {
        for ([_]u4{ @intCast(byte >> 4), @intCast(byte & 0xf) }) |nibble| {
            const step = decode_table[state][nibble];
            if (step.fail) return error.Compression;
            if (step.emits) {
                if (n == out.len) return error.HeaderListTooLarge;
                out[n] = step.symbol;
                n += 1;
            }
            state = step.next;
            accept = step.accept;
        }
    }
    if (!accept) return error.Compression;
    return n;
}

/// The length of `text` Huffman-coded, in bytes.
pub fn huffmanLen(text: []const u8) usize {
    var bits: usize = 0;
    for (text) |c| bits += huffman_codes[c][1];
    return (bits + 7) / 8;
}

/// Write `text` Huffman-coded, padded with ones.
pub fn huffmanEncode(w: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    var acc: u64 = 0;
    var bits: u7 = 0;
    for (text) |c| {
        const code, const len = huffman_codes[c];
        acc = (acc << len) | code;
        bits += len;
        while (bits >= 8) {
            bits -= 8;
            try w.writeByte(@truncate(acc >> @intCast(bits)));
        }
    }
    if (bits > 0) try w.writeByte(@truncate((acc << @intCast(8 - bits)) | (@as(u64, 0xff) >> @intCast(bits))));
}

/// Reads header blocks.
pub const Decoder = struct {
    table: Table,
    /// The table size the peer was told it may use: a size update past it
    /// is an error.
    limit: usize,

    /// A decoder with `table`, whose size is the limit told to the peer.
    pub fn init(table: Table) Decoder {
        return .{ .table = table, .limit = table.max_size };
    }

    /// Decode `block` into `fields`, every name and value copied into
    /// `out`; the fields read.
    pub fn decode(d: *Decoder, block: []const u8, out: []u8, fields: []Field) Error![]Field {
        var pos: usize = 0;
        var used: usize = 0;
        var n: usize = 0;
        var updates_allowed = true;
        while (pos < block.len) {
            const b = block[pos];
            if (b & 0xe0 == 0x20) {
                // A dynamic table size update: only before any field.
                if (!updates_allowed) return error.Compression;
                const size = try readInt(block, &pos, 5);
                if (size > d.limit) return error.Compression;
                d.table.setMaxSize(@intCast(size));
                continue;
            }
            updates_allowed = false;
            if (n == fields.len) return error.TooManyFields;
            if (b & 0x80 != 0) {
                const index = try readInt(block, &pos, 7);
                const name, const value = try d.lookup(index);
                fields[n] = .{ .name = try copy(out, &used, name), .value = try copy(out, &used, value) };
            } else {
                const indexing = b & 0x40 != 0;
                const never = !indexing and b & 0x10 != 0;
                const prefix: u4 = if (indexing) 6 else 4;
                const index = if (prefix == 6) try readInt(block, &pos, 6) else try readInt(block, &pos, 4);
                const name = if (index == 0) try readString(block, &pos, out, &used) else try copy(out, &used, (try d.lookup(index))[0]);
                const value = try readString(block, &pos, out, &used);
                if (indexing) d.table.add(name, value);
                fields[n] = .{ .name = name, .value = value, .never_index = never };
            }
            n += 1;
        }
        return fields[0..n];
    }

    fn lookup(d: *const Decoder, index: u64) Error!struct { []const u8, []const u8 } {
        if (index == 0) return error.Compression;
        if (index <= static_table.len) return static_table[@intCast(index - 1)];
        return d.table.get(@intCast(index - static_table.len - 1)) orelse error.Compression;
    }
};

fn copy(out: []u8, used: *usize, bytes: []const u8) Error![]const u8 {
    if (out.len - used.* < bytes.len) return error.HeaderListTooLarge;
    const dest = out[used.*..][0..bytes.len];
    @memcpy(dest, bytes);
    used.* += bytes.len;
    return dest;
}

fn readString(block: []const u8, pos: *usize, out: []u8, used: *usize) Error![]const u8 {
    if (pos.* >= block.len) return error.Compression;
    const huffman = block[pos.*] & 0x80 != 0;
    const len = try readInt(block, pos, 7);
    if (len > block.len - pos.*) return error.Compression;
    const raw = block[pos.*..][0..@intCast(len)];
    pos.* += raw.len;
    if (!huffman) return copy(out, used, raw);
    const n = try huffmanDecode(raw, out[used.*..]);
    const s = out[used.*..][0..n];
    used.* += n;
    return s;
}

/// Writes header blocks.
pub const Encoder = struct {
    table: Table,
    /// A table size the encoder must announce at the start of its next
    /// block, after the peer's setting changed it.
    pending_size: ?usize = null,

    pub fn init(table: Table) Encoder {
        return .{ .table = table };
    }

    /// The peer allows a table of at most `size`: the encoder uses that,
    /// within what its memory holds, and says so in its next block.
    pub fn setLimit(e: *Encoder, size: usize) void {
        const fits = @min(size, e.table.bytes.len / 2);
        e.table.setMaxSize(fits);
        e.pending_size = fits;
    }

    /// Write `fields` as one header block.
    pub fn encode(e: *Encoder, w: *Io.Writer, fields: []const Field) Io.Writer.Error!void {
        if (e.pending_size) |size| {
            try writeInt(w, 0x20, 5, size);
            e.pending_size = null;
        }
        for (fields) |f| try e.field(w, f);
    }

    fn field(e: *Encoder, w: *Io.Writer, f: Field) Io.Writer.Error!void {
        var name_index: ?usize = null;
        for (static_table, 1..) |entry, i| {
            if (!std.mem.eql(u8, entry[0], f.name)) continue;
            if (!f.never_index and std.mem.eql(u8, entry[1], f.value)) return writeInt(w, 0x80, 7, i);
            if (name_index == null) name_index = i;
        }
        for (0..e.table.count) |i| {
            const name, const value = e.table.get(i).?;
            if (!std.mem.eql(u8, name, f.name)) continue;
            const index = static_table.len + 1 + i;
            if (!f.never_index and std.mem.eql(u8, value, f.value)) return writeInt(w, 0x80, 7, index);
            if (name_index == null) name_index = index;
        }
        // Small fields are indexed for the next block; credentials never.
        const index_it = !f.never_index and f.name.len + f.value.len + 32 <= e.table.max_size / 2;
        const flags: u8 = if (f.never_index) 0x10 else if (index_it) 0x40 else 0x00;
        if (name_index) |i| {
            if (index_it) try writeInt(w, flags, 6, i) else try writeInt(w, flags, 4, i);
        } else {
            try w.writeByte(flags);
            try writeString(w, f.name);
        }
        try writeString(w, f.value);
        if (index_it) e.table.add(f.name, f.value);
    }
};

fn writeString(w: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    const coded = huffmanLen(text);
    if (coded < text.len) {
        try writeInt(w, 0x80, 7, coded);
        try huffmanEncode(w, text);
    } else {
        try writeInt(w, 0x00, 7, text.len);
        try w.writeAll(text);
    }
}

const testing = std.testing;

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // unreachable: the tests' hex is well formed
    return out;
}

test "RFC 7541's examples decode: a literal indexed under a new name, and Huffman-coded requests" {
    var bytes: [8192]u8 = undefined;
    var entries: [129]Table.Entry = undefined;
    var d: Decoder = .init(.init(&bytes, &entries, 4096));
    var out: [1024]u8 = undefined;
    var fields: [16]Field = undefined;
    // C.2.1
    const c21 = fromHex("400a637573746f6d2d6b65790d637573746f6d2d686561646572");
    const got = try d.decode(&c21, &out, &fields);
    try testing.expectEqualStrings("custom-key", got[0].name);
    try testing.expectEqualStrings("custom-header", got[0].value);
    try testing.expectEqual(@as(usize, 55), d.table.size);
    // C.4.1, a fresh decoder.
    var d2: Decoder = .init(.init(&bytes, &entries, 4096));
    const c41 = fromHex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
    const req = try d2.decode(&c41, &out, &fields);
    try testing.expectEqual(@as(usize, 4), req.len);
    try testing.expectEqualStrings(":authority", req[3].name);
    try testing.expectEqualStrings("www.example.com", req[3].value);
    // C.4.2: the authority from the table, and a Huffman-coded value.
    const c42 = fromHex("828684be5886a8eb10649cbf");
    const req2 = try d2.decode(&c42, &out, &fields);
    try testing.expectEqualStrings("www.example.com", req2[3].value);
    try testing.expectEqualStrings("cache-control", req2[4].name);
    try testing.expectEqualStrings("no-cache", req2[4].value);
}

test "what the encoder writes the decoder reads, across blocks, with a small table evicting" {
    var eb: [512]u8 = undefined;
    var ee: [9]Table.Entry = undefined;
    var db: [512]u8 = undefined;
    var de: [9]Table.Entry = undefined;
    var e: Encoder = .init(.init(&eb, &ee, 256));
    var d: Decoder = .init(.init(&db, &de, 256));
    var block: [1024]u8 = undefined;
    var out: [2048]u8 = undefined;
    var fields: [16]Field = undefined;
    for (0..20) |round| {
        var value_buf: [32]u8 = undefined;
        const value = try std.mem.print(&value_buf, "value-{d}", .{round % 7});
        const sent = [_]Field{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/a/long/path/that/repeats" },
            .{ .name = "x-round", .value = value },
            .{ .name = "authorization", .value = "Bearer secret", .never_index = true },
            .{ .name = "x-Ünicode-free", .value = "\x00\xff binary-ish" },
        };
        var w: Io.Writer = .fixed(&block);
        try e.encode(&w, &sent);
        const got = try d.decode(w.buffered(), &out, &fields);
        try testing.expectEqual(sent.len, got.len);
        for (sent, got) |s, g| {
            try testing.expectEqualStrings(s.name, g.name);
            try testing.expectEqualStrings(s.value, g.value);
            try testing.expectEqual(s.never_index, g.never_index);
        }
        try testing.expectEqual(e.table.size, d.table.size);
    }
}

test "broken blocks are refused, and a block past its buffer is too large" {
    var bytes: [8192]u8 = undefined;
    var entries: [129]Table.Entry = undefined;
    var d: Decoder = .init(.init(&bytes, &entries, 4096));
    var out: [8]u8 = undefined;
    var fields: [4]Field = undefined;
    try testing.expectError(error.Compression, d.decode(&.{0x80}, &out, &fields));
    try testing.expectError(error.Compression, d.decode(&.{0xbf}, &out, &fields));
    try testing.expectError(error.Compression, d.decode(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, &out, &fields));
    try testing.expectError(error.Compression, d.decode(&.{ 0x3f, 0xe2, 0x1f }, &out, &fields));
    try testing.expectError(error.HeaderListTooLarge, d.decode(&fromHex("400a637573746f6d2d6b65790d637573746f6d2d686561646572"), &out, &fields));
    // A Huffman string padded with a zero bit.
    var out2: [64]u8 = undefined;
    try testing.expectError(error.Compression, huffmanDecode(&.{0x00}, &out2));
    var enc: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&enc);
    try huffmanEncode(&w, "www.example.com");
    try testing.expectEqualSlices(u8, &fromHex("f1e3c2e5f23a6ba0ab90f4ff"), w.buffered());
}

test "fuzz: any block decodes or is refused, and what the encoder writes decodes back" {
    const shakedown = @import("shakedown");
    const inputs = @import("../testing/inputs.zig");
    const seeds = comptime [_][]const u8{ &fromHex("828684418cf1e3c2e5f23a6ba0ab90f4ff"), &fromHex("400a637573746f6d2d6b65790d637573746f6d2d686561646572"), &fromHex("3fe11f82") };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            const s = case.source;
            var buf: [512]u8 = undefined;
            const block = inputs.draw(case, &buf, &seeds, 64);
            var db: [Table.bytesFor(256)]u8 = undefined;
            var de: [Table.entriesFor(256)]Table.Entry = undefined;
            var d: Decoder = .init(.init(&db, &de, 256));
            var out: [1024]u8 = undefined;
            var fields: [32]Field = undefined;
            // Twice: a block that changed the table is read against it.
            // glint-ignore: Z026 -- refusing the block is a right answer; the property is that nothing breaks
            for (0..2) |_| _ = d.decode(block, &out, &fields) catch {};
            var eb: [Table.bytesFor(256)]u8 = undefined;
            var ee: [Table.entriesFor(256)]Table.Entry = undefined;
            var e: Encoder = .init(.init(&eb, &ee, 256));
            var d2: Decoder = .init(.init(&db, &de, 256));
            const names = [_][]const u8{ ":path", "accept", "x-a", "cookie", "authorization", "content-type" };
            var text: [8][24]u8 = undefined;
            var sent: [8]Field = undefined;
            const count = gen.intRange(s, usize, 0, sent.len);
            for (sent[0..count], text[0..count]) |*f, *t| {
                const len = gen.intRange(s, usize, 0, t.len);
                for (t[0..len]) |*b| b.* = gen.int(s, u8);
                f.* = .{ .name = gen.oneOf(s, []const u8, &names), .value = t[0..len], .never_index = gen.boolean(s) };
            }
            var wire_buf: [1024]u8 = undefined;
            var w: Io.Writer = .fixed(&wire_buf);
            try e.encode(&w, sent[0..count]);
            const got = try d2.decode(w.buffered(), &out, &fields);
            try testing.expectEqual(count, got.len);
            for (sent[0..count], got) |a, b| {
                try testing.expectEqualStrings(a.name, b.name);
                try testing.expectEqualSlices(u8, a.value, b.value);
            }
        }
        const gen = shakedown.gen;
    }.one, .{});
}
