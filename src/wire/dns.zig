//! DNS messages (RFC 1035), sans I/O: a query written, a response read
//! with its names decompressed within bounds, the records an HTTP client
//! asks for (A, AAAA, CNAME, and SVCB and HTTPS by RFC 9460), and the
//! resolver configuration of `resolv.conf`.
//!
//! Nothing here sends a message. A response is read in place: records are
//! views into it, and a name is decompressed into a buffer the caller
//! gives. Every length and pointer is checked against the message, a name
//! against 255 bytes and its labels against 63, and a compression pointer
//! must point before the name it continues, so no message makes a read
//! loop or leave its bytes.

const std = @import("std");

/// A record type.
pub const Type = enum(u16) {
    a = 1,
    cname = 5,
    aaaa = 28,
    opt = 41,
    svcb = 64,
    https = 65,
    _,
};

/// The Internet class, the only one queried.
pub const class_in: u16 = 1;

/// A response's code, EDNS's extension left out.
pub const Rcode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    /// The name does not exist.
    name_error = 3,
    not_implemented = 4,
    refused = 5,
    _,
};

pub const header_len = 12;
/// The longest name, in its wire form.
pub const max_name = 255;
pub const max_label = 63;
/// The UDP payload a query advertises by EDNS(0): 1232 bytes, which fits
/// any path's MTU (DNS flag day 2020).
pub const udp_payload = 1232;
/// The longest message: what TCP's two-byte length allows.
pub const max_message = 65535;

/// Why a query cannot be written.
pub const QueryError = error{
    /// Not a host name: an empty label, one past 63 bytes, a name past 255,
    /// or a byte no host name has.
    InvalidName,
    NoSpaceLeft,
};

/// Write into `out` a query for `name` (dotted, a trailing dot allowed) of
/// `kind`, recursion desired, with an EDNS(0) record advertising
/// `udp_payload`. The message is `out`'s start.
pub fn writeQuery(out: []u8, id: u16, name: []const u8, kind: Type) QueryError![]u8 {
    if (out.len < header_len) return error.NoSpaceLeft;
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x0100, .big); // RD
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 1, .big);
    var at: usize = header_len;
    at = try writeName(out, at, name);
    if (out.len - at < 4 + 11) return error.NoSpaceLeft;
    std.mem.writeInt(u16, out[at..][0..2], @backingInt(kind), .big);
    std.mem.writeInt(u16, out[at + 2 ..][0..2], class_in, .big);
    at += 4;
    // OPT: the root name, its type, the payload as its class, a zero TTL
    // (extended code, version 0, no flags), no options.
    const opt = [_]u8{ 0, 0, 41, udp_payload >> 8, udp_payload & 0xff, 0, 0, 0, 0, 0, 0 };
    @memcpy(out[at..][0..opt.len], &opt);
    return out[0 .. at + opt.len];
}

fn writeName(out: []u8, start: usize, name: []const u8) QueryError!usize {
    const text = if (name.len != 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    if (text.len == 0 or text.len + 2 > max_name) return error.InvalidName;
    var at = start;
    var labels = std.mem.splitScalar(u8, text, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > max_label) return error.InvalidName;
        for (label) |c| if (c <= ' ' or c >= 0x7f) return error.InvalidName;
        if (out.len - at < label.len + 1) return error.NoSpaceLeft;
        out[at] = @intCast(label.len); // safe: at most 63
        @memcpy(out[at + 1 ..][0..label.len], label);
        at += 1 + label.len;
    }
    if (out.len == at) return error.NoSpaceLeft;
    out[at] = 0;
    return at + 1;
}

/// Why a response cannot be read.
pub const ParseError = error{
    /// A length, pointer, label or count that does not fit the message.
    Malformed,
};

/// The flags of a message's header.
pub const Flags = struct {
    response: bool,
    opcode: u4,
    authoritative: bool,
    /// The answer did not fit: ask again over TCP.
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    rcode: Rcode,
};

/// A response, read in place.
pub const Message = struct {
    bytes: []const u8,
    id: u16,
    flags: Flags,
    questions: u16,
    answers_count: u16,
    authority_count: u16,
    additional_count: u16,
    /// Where the question section starts and the answers start.
    question_at: usize,
    answers_at: usize,

    /// Read the header and step over the questions.
    pub fn parse(bytes: []const u8) ParseError!Message {
        if (bytes.len < header_len) return error.Malformed;
        const bits = std.mem.readInt(u16, bytes[2..4], .big);
        var m: Message = .{
            .bytes = bytes,
            .id = std.mem.readInt(u16, bytes[0..2], .big),
            .flags = .{
                .response = bits & 0x8000 != 0,
                .opcode = @truncate(bits >> 11),
                .authoritative = bits & 0x0400 != 0,
                .truncated = bits & 0x0200 != 0,
                .recursion_desired = bits & 0x0100 != 0,
                .recursion_available = bits & 0x0080 != 0,
                .rcode = @fromBackingInt(@as(u4, @truncate(bits))),
            },
            .questions = std.mem.readInt(u16, bytes[4..6], .big),
            .answers_count = std.mem.readInt(u16, bytes[6..8], .big),
            .authority_count = std.mem.readInt(u16, bytes[8..10], .big),
            .additional_count = std.mem.readInt(u16, bytes[10..12], .big),
            .question_at = header_len,
            .answers_at = header_len,
        };
        var at: usize = header_len;
        for (0..m.questions) |_| {
            at = try skipName(bytes, at);
            if (bytes.len - at < 4) return error.Malformed;
            at += 4;
        }
        m.answers_at = at;
        return m;
    }

    /// Whether this is the response to the query `id` for `name` of
    /// `kind`: the same id, a response, and the one question echoed.
    pub fn answers(m: *const Message, id: u16, name: []const u8, kind: Type) ParseError!bool {
        if (m.id != id or !m.flags.response or m.questions != 1) return false;
        const end = try skipName(m.bytes, m.question_at);
        if (m.bytes.len - end < 4) return error.Malformed;
        if (std.mem.readInt(u16, m.bytes[end..][0..2], .big) != @backingInt(kind)) return false;
        return nameIs(m.bytes, m.question_at, name);
    }

    /// The answer section's records.
    pub fn records(m: *const Message) Records {
        return .{ .bytes = m.bytes, .at = m.answers_at, .left = m.answers_count };
    }
};

/// One resource record, its data a view into the message.
pub const Record = struct {
    /// Where its owner name starts in the message.
    name_at: usize,
    kind: Type,
    class: u16,
    ttl: u32,
    /// Where its data starts, for names inside it.
    data_at: usize,
    data: []const u8,
};

/// The records of a section, read one at a time.
pub const Records = struct {
    bytes: []const u8,
    at: usize,
    left: u16,

    pub fn next(r: *Records) ParseError!?Record {
        if (r.left == 0) return null;
        r.left -= 1;
        const name_at = r.at;
        var at = try skipName(r.bytes, r.at);
        if (r.bytes.len - at < 10) return error.Malformed;
        const fixed = r.bytes[at..][0..10];
        const len = std.mem.readInt(u16, fixed[8..10], .big);
        at += 10;
        if (r.bytes.len - at < len) return error.Malformed;
        r.at = at + len;
        return .{
            .name_at = name_at,
            .kind = @fromBackingInt(std.mem.readInt(u16, fixed[0..2], .big)),
            .class = std.mem.readInt(u16, fixed[2..4], .big),
            .ttl = std.mem.readInt(u32, fixed[4..8], .big),
            .data_at = at,
            .data = r.bytes[at..][0..len],
        };
    }
};

/// The end of the name at `at`, compressed or not, without following it.
pub fn skipName(bytes: []const u8, start: usize) ParseError!usize {
    var at = start;
    var len: usize = 1;
    while (true) {
        if (at >= bytes.len) return error.Malformed;
        const b = bytes[at];
        switch (b >> 6) {
            0 => {
                if (b == 0) return at + 1;
                len += b + 1;
                if (len > max_name) return error.Malformed;
                at += 1 + b;
            },
            3 => {
                if (bytes.len - at < 2) return error.Malformed;
                return at + 2;
            },
            else => return error.Malformed,
        }
    }
}

/// The end of the uncompressed name at `start`: a pointer in it is
/// malformed.
fn skipPlainName(bytes: []const u8, start: usize) ParseError!usize {
    var at = start;
    var len: usize = 1;
    while (true) {
        if (at >= bytes.len) return error.Malformed;
        const b = bytes[at];
        if (b == 0) return at + 1;
        if (b > max_label) return error.Malformed;
        len += b + 1;
        if (len > max_name) return error.Malformed;
        at += 1 + b;
    }
}

/// The name at `start` in `bytes`, decompressed into `out` as dotted text
/// without the root's dot; empty for the root. A pointer must point
/// before the label it stands for, so a name cannot loop.
pub fn readName(bytes: []const u8, start: usize, out: *[max_name]u8) ParseError![]u8 {
    var at = start;
    var len: usize = 0;
    var wire_len: usize = 1;
    // The lowest offset this name has read from: a pointer must go below it.
    var floor = start;
    while (true) {
        if (at >= bytes.len) return error.Malformed;
        const b = bytes[at];
        switch (b >> 6) {
            0 => {
                if (b == 0) return out[0..len];
                if (b > max_label) return error.Malformed;
                wire_len += b + 1;
                if (wire_len > max_name or bytes.len - at - 1 < b) return error.Malformed;
                if (len != 0) {
                    out[len] = '.';
                    len += 1;
                }
                @memcpy(out[len..][0..b], bytes[at + 1 ..][0..b]);
                len += b;
                at += 1 + b;
            },
            3 => {
                if (bytes.len - at < 2) return error.Malformed;
                const target = std.mem.readInt(u16, bytes[at..][0..2], .big) & 0x3fff;
                if (target >= floor) return error.Malformed;
                floor = target;
                at = target;
            },
            else => return error.Malformed,
        }
    }
}

/// Whether the name at `start` is `name` (dotted, a trailing dot allowed),
/// compared without case.
pub fn nameIs(bytes: []const u8, start: usize, name: []const u8) ParseError!bool {
    var buffer: [max_name]u8 = undefined;
    const got = try readName(bytes, start, &buffer);
    const want = if (name.len != 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    return std.ascii.eqlIgnoreCase(got, want);
}

/// An address record's address: four bytes for A, sixteen for AAAA; null
/// for any other record, or one of the wrong length.
pub const Address = union(enum) {
    ip4: [4]u8,
    ip6: [16]u8,

    pub fn of(r: Record) ?Address {
        return switch (r.kind) {
            .a => if (r.data.len == 4) .{ .ip4 = r.data[0..4].* } else null,
            .aaaa => if (r.data.len == 16) .{ .ip6 = r.data[0..16].* } else null,
            else => null,
        };
    }
};

/// The name a CNAME record points to, decompressed into `out`.
pub fn cnameTarget(bytes: []const u8, r: Record, out: *[max_name]u8) ParseError![]u8 {
    if (r.kind != .cname) return error.Malformed;
    const name = try readName(bytes, r.data_at, out);
    if (try skipName(bytes, r.data_at) != r.data_at + r.data.len) return error.Malformed;
    return name;
}

/// The keys of an SVCB or HTTPS record's parameters (RFC 9460 §14.3.2).
pub const Key = enum(u16) {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
    _,
};

/// An SVCB or HTTPS record (RFC 9460): a priority, 0 for AliasMode; a
/// target, empty for the owner itself; and its parameters, checked as the
/// RFC says when it is read.
pub const Service = struct {
    priority: u16,
    target: []const u8,
    /// The parameters' bytes, keys in ascending order, each well formed.
    params: []const u8,

    /// Read `r`, the target decompressed into `out`. A record whose
    /// parameters break RFC 9460's rules (keys out of order or repeated, a
    /// value of the wrong form) is malformed.
    pub fn parse(r: Record, out: *[max_name]u8) ParseError!Service {
        if (r.kind != .svcb and r.kind != .https) return error.Malformed;
        if (r.data.len < 3) return error.Malformed;
        const priority = std.mem.readInt(u16, r.data[0..2], .big);
        // The target is never compressed (RFC 9460 §2.2), so it ends in
        // the record's data.
        const target_end = try skipPlainName(r.data, 2);
        const target = try readName(r.data, 2, out);
        const params = r.data[target_end..];
        var it: Params = .{ .bytes = params };
        var last: ?u16 = null;
        while (try it.next()) |p| {
            const key: u16 = @backingInt(p.key);
            if (last) |l| if (key <= l) return error.Malformed;
            last = key;
            try checkParam(p);
        }
        return .{ .priority = priority, .target = target, .params = params };
    }

    /// Whether a client may use the record: every key it names mandatory
    /// is one this reads (§8), and it is not AliasMode.
    pub fn usable(s: Service) bool {
        if (s.priority == 0) return false;
        const m = s.param(.mandatory) orelse return true;
        var i: usize = 0;
        while (i + 2 <= m.len) : (i += 2) switch (@as(Key, @fromBackingInt(std.mem.readInt(u16, m[i..][0..2], .big)))) {
            .alpn, .no_default_alpn, .port, .ipv4hint, .ech, .ipv6hint => {},
            .mandatory, _ => return false,
        };
        return true;
    }

    /// The value of the parameter `key`, when the record has it.
    pub fn param(s: Service, key: Key) ?[]const u8 {
        var it: Params = .{ .bytes = s.params };
        while (it.next() catch return null) |p| if (p.key == key) return p.value;
        return null;
    }

    /// The protocols the record names by `alpn`, in its order.
    pub fn alpn(s: Service) Alpn {
        return .{ .bytes = s.param(.alpn) orelse "" };
    }

    /// Whether `no-default-alpn` takes the default protocol away.
    pub fn noDefaultAlpn(s: Service) bool {
        return s.param(.no_default_alpn) != null;
    }

    pub fn port(s: Service) ?u16 {
        const v = s.param(.port) orelse return null;
        return std.mem.readInt(u16, v[0..2], .big);
    }

    /// The IPv4 hints, four bytes each.
    pub fn ipv4Hints(s: Service) []const u8 {
        return s.param(.ipv4hint) orelse "";
    }

    /// The IPv6 hints, sixteen bytes each.
    pub fn ipv6Hints(s: Service) []const u8 {
        return s.param(.ipv6hint) orelse "";
    }

    /// The ECHConfigList, for TLS's Encrypted Client Hello.
    pub fn ech(s: Service) ?[]const u8 {
        return s.param(.ech);
    }
};

/// One parameter of a service record.
pub const Param = struct { key: Key, value: []const u8 };

/// A service record's parameters, read one at a time.
pub const Params = struct {
    bytes: []const u8,
    at: usize = 0,

    pub fn next(p: *Params) ParseError!?Param {
        if (p.at == p.bytes.len) return null;
        if (p.bytes.len - p.at < 4) return error.Malformed;
        const key = std.mem.readInt(u16, p.bytes[p.at..][0..2], .big);
        const len = std.mem.readInt(u16, p.bytes[p.at + 2 ..][0..2], .big);
        p.at += 4;
        if (p.bytes.len - p.at < len) return error.Malformed;
        const value = p.bytes[p.at..][0..len];
        p.at += len;
        return .{ .key = @fromBackingInt(key), .value = value };
    }
};

fn checkParam(p: Param) ParseError!void {
    const v = p.value;
    switch (p.key) {
        .mandatory => {
            if (v.len == 0 or v.len % 2 != 0) return error.Malformed;
            var i: usize = 0;
            var last: ?u16 = null;
            while (i < v.len) : (i += 2) {
                const k = std.mem.readInt(u16, v[i..][0..2], .big);
                // Ascending, no repeats, and never `mandatory` itself.
                if (k == 0) return error.Malformed;
                if (last) |l| if (k <= l) return error.Malformed;
                last = k;
            }
        },
        .alpn => {
            if (v.len == 0) return error.Malformed;
            var it: Alpn = .{ .bytes = v };
            while (try it.next()) |_| {}
        },
        .no_default_alpn => if (v.len != 0) return error.Malformed,
        .port => if (v.len != 2) return error.Malformed,
        .ipv4hint => if (v.len == 0 or v.len % 4 != 0) return error.Malformed,
        .ipv6hint => if (v.len == 0 or v.len % 16 != 0) return error.Malformed,
        .ech => {},
        _ => {},
    }
}

/// The protocol ids of an `alpn` value, each a length and its bytes.
pub const Alpn = struct {
    bytes: []const u8,
    at: usize = 0,

    pub fn next(a: *Alpn) ParseError!?[]const u8 {
        if (a.at == a.bytes.len) return null;
        const len = a.bytes[a.at];
        if (len == 0 or a.bytes.len - a.at - 1 < len) return error.Malformed;
        const id = a.bytes[a.at + 1 ..][0..len];
        a.at += 1 + len;
        return id;
    }
};

/// A resolver's configuration, as `resolv.conf` writes it.
pub const Config = struct {
    /// The name servers, at most three, as text: an IPv4 or IPv6 address.
    servers: [max_servers][]const u8 = undefined,
    server_count: u8 = 0,
    /// The domains a short name is tried under, at most six.
    search: [max_search][]const u8 = undefined,
    search_count: u8 = 0,
    /// A name with fewer dots than this is tried under the search domains
    /// first.
    ndots: u8 = 1,
    /// Seconds a server is waited for, and the rounds over the servers.
    timeout_seconds: u8 = 5,
    attempts: u8 = 2,
    /// Start at a different server each query.
    rotate: bool = false,

    pub const max_servers = 3;
    pub const max_search = 6;

    /// The configuration in `text`; its slices point into it. Lines and
    /// options this does not know are passed over, as the C library passes
    /// them; numbers past their limits are held to them (`ndots` 15,
    /// `timeout` 30, `attempts` 5).
    pub fn parse(text: []const u8) Config {
        var c: Config = .{};
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const comment = std.mem.findAny(u8, raw, "#;") orelse raw.len;
            var words = std.mem.tokenizeAny(u8, raw[0..comment], " \t\r");
            const keyword = words.next() orelse continue;
            if (std.mem.eql(u8, keyword, "nameserver")) {
                const server = words.next() orelse continue;
                if (c.server_count < max_servers) {
                    c.servers[c.server_count] = server;
                    c.server_count += 1;
                }
            } else if (std.mem.eql(u8, keyword, "search") or std.mem.eql(u8, keyword, "domain")) {
                // The last of either wins, as in the C library.
                c.search_count = 0;
                while (words.next()) |d| {
                    if (c.search_count == max_search) break;
                    c.search[c.search_count] = d;
                    c.search_count += 1;
                }
            } else if (std.mem.eql(u8, keyword, "options")) {
                while (words.next()) |o| {
                    if (std.mem.eql(u8, o, "rotate")) {
                        c.rotate = true;
                    } else if (number(o, "ndots:", 15)) |n| {
                        c.ndots = n;
                    } else if (number(o, "timeout:", 30)) |n| {
                        c.timeout_seconds = @max(n, 1);
                    } else if (number(o, "attempts:", 5)) |n| {
                        c.attempts = @max(n, 1);
                    }
                }
            }
        }
        return c;
    }

    fn number(option: []const u8, prefix: []const u8, max: u8) ?u8 {
        if (!std.mem.startsWith(u8, option, prefix)) return null;
        const n = std.fmt.parseUnsigned(u32, option[prefix.len..], 10) catch return null;
        return @intCast(@min(n, max)); // safe: held to `max`, a u8
    }

    pub fn serverList(c: *const Config) []const []const u8 {
        return c.servers[0..c.server_count];
    }

    pub fn searchList(c: *const Config) []const []const u8 {
        return c.search[0..c.search_count];
    }

    /// The names to ask for `host`, in order, as the C library tries them:
    /// a name ending in a dot as it is; one with `ndots` dots or more as it
    /// is, then under each search domain; a shorter one under each search
    /// domain first.
    pub fn candidates(c: *const Config, host: []const u8) Candidates {
        return .{ .config = c, .host = host };
    }
};

/// The names a host is asked as, written into a buffer one at a time.
pub const Candidates = struct {
    config: *const Config,
    host: []const u8,
    step: u8 = 0,

    pub fn next(it: *Candidates, buffer: *[max_name]u8) ?[]const u8 {
        const host = it.host;
        if (host.len != 0 and host[host.len - 1] == '.') {
            if (it.step != 0) return null;
            it.step = 1;
            return host;
        }
        const search = it.config.searchList();
        const dots = std.mem.count(u8, host, ".");
        const plain_first = dots >= it.config.ndots;
        while (it.step <= search.len) {
            const step = it.step;
            it.step += 1;
            // The plain name's turn: first, or after every search domain.
            const plain_turn: u8 = if (plain_first) 0 else @intCast(search.len); // safe: at most six domains
            if (step == plain_turn) return host;
            const index = if (plain_first) step - 1 else step;
            const domain = search[index];
            if (host.len + 1 + domain.len > max_name - 2) continue;
            @memcpy(buffer[0..host.len], host);
            buffer[host.len] = '.';
            @memcpy(buffer[host.len + 1 ..][0..domain.len], domain);
            return buffer[0 .. host.len + 1 + domain.len];
        }
        return null;
    }
};

const testing = std.testing;

/// A response to `query`, with `records` (each a whole record whose owner
/// is a pointer to the question's name) in its answer section.
fn testResponse(out: []u8, query: []const u8, rcode: u4, records: []const []const u8) []u8 {
    // The question, without the OPT record the query carries.
    const question_end = skipName(query, header_len) catch unreachable; // unreachable: the tests' own query
    const q_len = question_end + 4;
    @memcpy(out[0..q_len], query[0..q_len]);
    std.mem.writeInt(u16, out[2..4], 0x8180 | @as(u16, rcode), .big);
    std.mem.writeInt(u16, out[6..8], @intCast(records.len), .big); // safe: the tests pass a few records
    std.mem.writeInt(u16, out[10..12], 0, .big);
    var at = q_len;
    for (records) |r| {
        @memcpy(out[at..][0..r.len], r);
        at += r.len;
    }
    return out[0..at];
}

test "a query is written with its name, type and EDNS, and names are refused as DNS refuses them" {
    var buf: [512]u8 = undefined;
    const q = try writeQuery(&buf, 0xbeef, "Example.com.", .aaaa);
    try testing.expectEqualSlices(u8, &.{ 0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1 }, q[0..12]);
    try testing.expectEqualSlices(u8, "\x07Example\x03com\x00\x00\x1c\x00\x01", q[12..29]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0 }, q[29..]);
    try testing.expectError(error.InvalidName, writeQuery(&buf, 1, "a..b", .a));
    try testing.expectError(error.InvalidName, writeQuery(&buf, 1, "", .a));
    try testing.expectError(error.InvalidName, writeQuery(&buf, 1, "a b.c", .a));
    var long_label: [64]u8 = @splat('a');
    try testing.expectError(error.InvalidName, writeQuery(&buf, 1, &long_label, .a));
    var long_name: [254]u8 = @splat('a');
    for (1..long_name.len / 2) |i| long_name[i * 2 - 1] = '.';
    try testing.expectError(error.InvalidName, writeQuery(&buf, 1, &long_name, .a));
    var small: [20]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, writeQuery(&small, 1, "example.com", .a));
}

test "a response's records are read, names decompressed, and the question checked" {
    var qbuf: [512]u8 = undefined;
    const q = try writeQuery(&qbuf, 7, "www.example.com", .a);
    var rbuf: [512]u8 = undefined;
    const cname = "\xc0\x0c\x00\x05\x00\x01\x00\x00\x01\x2c\x00\x06\x03cdn\xc0\x10";
    const a = "\xc0\x2d\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22";
    const r = testResponse(&rbuf, q, 0, &.{ cname, a });
    const m = try Message.parse(r);
    try testing.expect(try m.answers(7, "WWW.example.com.", .a));
    try testing.expect(!try m.answers(8, "www.example.com", .a));
    try testing.expect(!try m.answers(7, "example.com", .a));
    try testing.expect(!try m.answers(7, "www.example.com", .aaaa));
    var it = m.records();
    const first = (try it.next()).?;
    var name_buf: [max_name]u8 = undefined;
    try testing.expectEqualStrings("cdn.example.com", try cnameTarget(r, first, &name_buf));
    try testing.expectEqual(@as(u32, 300), first.ttl);
    const second = (try it.next()).?;
    try testing.expectEqualStrings("cdn.example.com", try readName(r, second.name_at, &name_buf));
    try testing.expectEqual(Address{ .ip4 = .{ 93, 184, 216, 34 } }, Address.of(second).?);
    try testing.expectEqual(null, try it.next());
}

test "names that loop, point forward, or pass their bounds are malformed" {
    var out: [max_name]u8 = undefined;
    // A pointer to itself, one forward, one past the end.
    const header: [12]u8 = @splat(0);
    try testing.expectError(error.Malformed, readName(&header ++ "\xc0\x0c", 12, &out));
    try testing.expectError(error.Malformed, readName(&header ++ "\xc0\x0e\x00", 12, &out));
    try testing.expectError(error.Malformed, readName(&header ++ "\xc0", 12, &out));
    // Two names pointing at each other.
    try testing.expectError(error.Malformed, readName(&header ++ "\x01a\xc0\x10\x01b\xc0\x0c", 16, &out));
    // A label past the message, and the reserved label types.
    try testing.expectError(error.Malformed, readName(&header ++ "\x05ab", 12, &out));
    try testing.expectError(error.Malformed, readName(&header ++ "\x40", 12, &out));
    try testing.expectError(error.Malformed, readName(&header ++ "\x80", 12, &out));
    // Past 255 bytes through pointers back.
    var long: [12 + 4 * 64 + 1]u8 = undefined;
    @memcpy(long[0..12], &header);
    for (0..4) |i| {
        long[12 + i * 64] = 63;
        @memset(long[12 + i * 64 + 1 ..][0..63], 'x');
    }
    long[long.len - 1] = 0;
    try testing.expectError(error.Malformed, readName(&long, 12, &out));
    try testing.expectError(error.Malformed, Message.parse("\x00\x01"));
}

test "an HTTPS record's parameters are read, and broken ones refused" {
    const rdata = "\x00\x01\x00" ++ // priority 1, the owner itself
        "\x00\x01\x00\x06\x02h2\x02h3" ++ // alpn
        "\x00\x03\x00\x02\x01\xbb" ++ // port 443
        "\x00\x04\x00\x04\x01\x02\x03\x04" ++ // ipv4hint
        "\x00\x05\x00\x03ech" ++ // ech
        "\x00\x06\x00\x10" ++ "\x20\x01\x0d\xb8" ++ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    const bytes = rdata;
    const record: Record = .{ .name_at = 0, .kind = .https, .class = 1, .ttl = 1, .data_at = 0, .data = bytes };
    var out: [max_name]u8 = undefined;
    const s = try Service.parse(record, &out);
    try testing.expectEqual(1, s.priority);
    try testing.expectEqualStrings("", s.target);
    try testing.expect(s.usable());
    var protocols = s.alpn();
    try testing.expectEqualStrings("h2", (try protocols.next()).?);
    try testing.expectEqualStrings("h3", (try protocols.next()).?);
    try testing.expectEqual(null, try protocols.next());
    try testing.expectEqual(443, s.port().?);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, s.ipv4Hints());
    try testing.expectEqualStrings("ech", s.ech().?);
    try testing.expectEqual(16, s.ipv6Hints().len);
    const bad = [_][]const u8{
        "\x00\x01\x00\x00\x03\x00\x02\x01\xbb\x00\x01\x00\x03\x02h2", // keys out of order
        "\x00\x01\x00\x00\x03\x00\x01\x01", // port of one byte
        "\x00\x01\x00\x00\x01\x00\x00", // empty alpn
        "\x00\x01\x00\x00\x01\x00\x03\x05h2", // alpn id past its value
        "\x00\x01\x00\x00\x04\x00\x03\x01\x02\x03", // ipv4hint not whole
        "\x00\x01\x00\x00\x00\x00\x02\x00\x00", // mandatory naming itself
        "\x00\x01\x00\x00\x02\x00\x01\x00", // no-default-alpn with a value
        "\x00\x01\xc0\x00", // a compressed target
    };
    for (bad) |b| {
        const r: Record = .{ .name_at = 0, .kind = .https, .class = 1, .ttl = 1, .data_at = 0, .data = b };
        try testing.expectError(error.Malformed, Service.parse(r, &out));
    }
    // A mandatory key this does not read makes the record unusable; an
    // alias names its target.
    const unknown = "\x00\x01\x00\x00\x00\x00\x02\x00\x09\x00\x09\x00\x00";
    const u = try Service.parse(.{ .name_at = 0, .kind = .https, .class = 1, .ttl = 1, .data_at = 0, .data = unknown }, &out);
    try testing.expect(!u.usable());
    const alias = "\x00\x00\x03svc\x07example\x00";
    const al = try Service.parse(.{ .name_at = 0, .kind = .https, .class = 1, .ttl = 1, .data_at = 0, .data = alias }, &out);
    try testing.expectEqual(0, al.priority);
    try testing.expectEqualStrings("svc.example", al.target);
    try testing.expect(!al.usable());
}

test "resolv.conf is read as the C library reads it, and names are tried in its order" {
    const c: Config = .parse(
        \\# a comment
        \\nameserver 10.0.0.1
        \\nameserver 2001:db8::1 ; trailing
        \\domain old.example
        \\search corp.example lab.example
        \\nameserver 10.0.0.2
        \\nameserver 10.0.0.3
        \\options ndots:2 timeout:3 attempts:9 rotate unknown
        \\bogus line
    );
    try testing.expectEqual(3, c.serverList().len);
    try testing.expectEqualStrings("2001:db8::1", c.serverList()[1]);
    try testing.expectEqual(2, c.searchList().len);
    try testing.expectEqual(2, c.ndots);
    try testing.expectEqual(3, c.timeout_seconds);
    try testing.expectEqual(5, c.attempts);
    try testing.expect(c.rotate);
    var buf: [max_name]u8 = undefined;
    var short = c.candidates("db");
    try testing.expectEqualStrings("db.corp.example", short.next(&buf).?);
    try testing.expectEqualStrings("db.lab.example", short.next(&buf).?);
    try testing.expectEqualStrings("db", short.next(&buf).?);
    try testing.expectEqual(null, short.next(&buf));
    var long = c.candidates("www.example.com");
    try testing.expectEqualStrings("www.example.com", long.next(&buf).?);
    try testing.expectEqualStrings("www.example.com.corp.example", long.next(&buf).?);
    var absolute = c.candidates("db.");
    try testing.expectEqualStrings("db.", absolute.next(&buf).?);
    try testing.expectEqual(null, absolute.next(&buf));
}

test "fuzz: any message is read or refused, never past its bytes" {
    const shakedown = @import("shakedown");
    const inputs = @import("../testing/inputs.zig");
    const seed = "\x00\x07\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03www\x07example\x03com\x00\x00\x41\x00\x01" ++
        "\xc0\x0c\x00\x05\x00\x01\x00\x00\x01\x2c\x00\x06\x03cdn\xc0\x10" ++
        "\xc0\x2d\x00\x41\x00\x01\x00\x00\x00\x3c\x00\x10\x00\x01\x00\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x01\xbb";
    const seeds = [_][]const u8{seed};
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var buf: [512]u8 = undefined;
            const bytes = inputs.draw(case, &buf, &seeds, 96);
            const m = Message.parse(bytes) catch return;
            _ = m.answers(7, "www.example.com", .https) catch false;
            var it = m.records();
            var out: [max_name]u8 = undefined;
            while (it.next() catch return) |r| {
                try testing.expect(r.data_at + r.data.len <= bytes.len);
                const name = readName(bytes, r.name_at, &out) catch continue;
                try testing.expect(name.len <= max_name);
                if (r.kind == .https or r.kind == .svcb) {
                    const s = Service.parse(r, &out) catch continue;
                    var protocols = s.alpn();
                    while (try protocols.next()) |_| {}
                    _ = s.usable();
                    _ = s.port();
                }
            }
        }
    }.one, .{});
}
