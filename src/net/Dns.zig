//! A resolver that speaks DNS itself, over a transport: a stub that asks
//! the configured name servers over UDP, and over TCP when an answer is
//! truncated, or anything else that carries a DNS message, such as DNS
//! over HTTPS (`client.Doh`). It asks for a name's AAAA and A records, the
//! two at once when a task can be had, follows the CNAMEs in the answer,
//! and tries the search domains as `resolv.conf` orders them. `https`
//! answers a name's HTTPS records (RFC 9460).
//!
//! The system's lookup stays the default: a client takes a `Dns` only when
//! asked (`Options.resolver`).

const std = @import("std");
const reactor = @import("reactor");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const dns = @import("uplink.wire").dns;
const span = @import("../span.zig");
const Duration = span.Duration;
const Resolver = @import("Resolver.zig");
const Timed = @import("Timed.zig");

const Dns = @This();

transport: Transport,
/// The search domains and `ndots`; its slices must outlive the resolver.
config: dns.Config = .{},

/// What carries a query to a server and its answer back.
pub const Transport = struct {
    context: ?*anyopaque,
    /// Send `query`, a whole message, and return the answer to it in
    /// `answer`, its id and question checked.
    exchangeFn: *const fn (io: Io, context: ?*anyopaque, query: []const u8, answer: []u8) ExchangeError![]u8,

    pub fn exchange(t: Transport, io: Io, query: []const u8, answer: []u8) ExchangeError![]u8 {
        return t.exchangeFn(io, t.context, query, answer);
    }
};

/// Why a query got no answer.
pub const ExchangeError = error{
    /// No server answered in time, or every one failed.
    NoAnswer,
    Canceled,
};

pub fn resolver(d: *const Dns) Resolver {
    return .{ .context = @constCast(d), .lookupFn = lookupFn, .serviceFn = serviceFn }; // safe: a lookup only reads through the pointer
}

/// The ids of queries: random, so an answer cannot be guessed.
fn queryId(io: Io) u16 {
    var bytes: [2]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u16, &bytes, .little);
}

/// What one name's question found.
const Found = union(enum) {
    /// Addresses, possibly none for this type.
    addresses: usize,
    /// The name does not exist: the next search domain is tried.
    no_name,
};

fn lookupFn(io: Io, context: ?*anyopaque, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) Resolver.LookupError![]IpAddress {
    const d: *const Dns = @ptrCast(@alignCast(context.?)); // safe: `resolver` passes a Dns
    var candidates = d.config.candidates(host);
    var name_buf: [dns.max_name]u8 = undefined;
    while (candidates.next(&name_buf)) |name| {
        const n = d.lookupName(io, name, port, family, out) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.InvalidName => return error.InvalidHostName,
            error.NoName => continue,
            error.NoAnswer => return error.NameNotResolved,
        };
        if (n == 0) return error.NameNotResolved;
        return out[0..n];
    }
    return error.NameNotResolved;
}

const NameError = error{ InvalidName, NoName, NoAnswer, Canceled };

/// `name`'s addresses, IPv6 first, into `out`; how many.
fn lookupName(d: *const Dns, io: Io, name: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) NameError!usize {
    if (family) |f| return switch (try d.ask(io, name, if (f == .ip6) .aaaa else .a, port, out)) {
        .addresses => |n| n,
        .no_name => error.NoName,
    };
    // AAAA beside A when a task can be had; one after the other otherwise.
    var v6: [reactor.net.max_addresses]IpAddress = undefined;
    const half = @min(out.len, v6.len);
    var aaaa_task = io.concurrent(ask, .{ d, io, name, dns.Type.aaaa, port, v6[0..half] }) catch null;
    const a_found = d.ask(io, name, .a, port, out) catch |err| {
        // glint-ignore: Z026 -- this name's lookup failed; the other family's answer goes with it
        if (aaaa_task) |*t| _ = t.cancel(io) catch {};
        return err;
    };
    const aaaa_found: NameError!Found = if (aaaa_task) |*t| t.await(io) else d.ask(io, name, .aaaa, port, v6[0..half]);
    const six: usize = switch (aaaa_found catch |err| switch (err) {
        // One family failing leaves the other's answer.
        error.NoAnswer => Found{ .addresses = 0 },
        else => |e| return e,
    }) {
        .addresses => |n| n,
        .no_name => 0,
    };
    const four: usize = switch (a_found) {
        .addresses => |n| n,
        .no_name => if (six == 0) return error.NoName else 0,
    };
    // IPv6 first, the IPv4 after them, as many as fit.
    const keep_four = @min(four, out.len -| six);
    @memmove(out[@min(six, out.len)..][0..keep_four], out[0..keep_four]);
    const keep_six = @min(six, out.len);
    @memcpy(out[0..keep_six], v6[0..keep_six]);
    return keep_six + keep_four;
}

/// One question: `name`'s records of `kind`, the addresses in `out`.
fn ask(d: *const Dns, io: Io, name: []const u8, kind: dns.Type, port: u16, out: []IpAddress) NameError!Found {
    var query_buf: [dns.max_name + 64]u8 = undefined;
    const id = queryId(io);
    const query = dns.writeQuery(&query_buf, id, name, kind) catch return error.InvalidName;
    var answer_buf: [dns.max_message]u8 = undefined;
    const answer = d.transport.exchange(io, query, &answer_buf) catch |err| return switch (err) {
        error.NoAnswer => error.NoAnswer,
        error.Canceled => error.Canceled,
    };
    const m = dns.Message.parse(answer) catch return error.NoAnswer;
    if (!(m.answers(id, name, kind) catch false)) return error.NoAnswer;
    switch (m.flags.rcode) {
        .no_error => {},
        .name_error => return .no_name,
        else => return error.NoAnswer,
    }
    return .{ .addresses = collect(answer, &m, name, kind, port, out) catch return error.NoAnswer };
}

/// The addresses the answer gives `name`, following its CNAMEs.
fn collect(bytes: []const u8, m: *const dns.Message, name: []const u8, kind: dns.Type, port: u16, out: []IpAddress) dns.ParseError!usize {
    var owner_buf: [dns.max_name]u8 = undefined;
    var owner: []const u8 = name;
    if (owner.len != 0 and owner[owner.len - 1] == '.') owner = owner[0 .. owner.len - 1];
    @memcpy(owner_buf[0..owner.len], owner);
    owner = owner_buf[0..owner.len];
    // A chain no longer than the records in the answer.
    var hops: usize = 0;
    while (hops <= m.answers_count) : (hops += 1) {
        var records = m.records();
        var next: ?[]const u8 = null;
        var target_buf: [dns.max_name]u8 = undefined;
        var n: usize = 0;
        while (try records.next()) |r| {
            if (r.class != dns.class_in) continue;
            if (!try dns.nameIs(bytes, r.name_at, owner)) continue;
            if (r.kind == .cname) {
                next = try dns.cnameTarget(bytes, r, &target_buf);
            } else if (r.kind == kind and n < out.len) {
                const address = dns.Address.of(r) orelse continue;
                out[n] = switch (address) {
                    .ip4 => |b| .{ .ip4 = .{ .bytes = b, .port = port } },
                    .ip6 => |b| .{ .ip6 = .{ .bytes = b, .port = port } },
                };
                n += 1;
            }
        }
        if (n != 0) return n;
        const target = next orelse return 0;
        @memcpy(owner_buf[0..target.len], target);
        owner = owner_buf[0..target.len];
    }
    return 0;
}

/// A name's HTTPS records (RFC 9460): the ServiceMode records a client can
/// use, the most preferred first, each target the name it is for when it
/// names none, AliasMode records followed; owned by `gpa`. Null when the
/// name has none.
pub fn https(d: *const Dns, io: Io, gpa: Allocator, host: []const u8) (NameError || Allocator.Error)!?Resolver.Binding {
    var name_buf: [dns.max_name]u8 = undefined;
    const trimmed = if (host.len != 0 and host[host.len - 1] == '.') host[0 .. host.len - 1] else host;
    if (trimmed.len > name_buf.len) return error.InvalidName;
    @memcpy(name_buf[0..trimmed.len], trimmed);
    var name: []const u8 = name_buf[0..trimmed.len];
    // RFC 9460 §3: a client follows a few aliases, then gives up.
    for (0..max_aliases) |_| {
        var query_buf: [dns.max_name + 64]u8 = undefined;
        const id = queryId(io);
        const query = dns.writeQuery(&query_buf, id, name, .https) catch return error.InvalidName;
        var answer_buf: [dns.max_message]u8 = undefined;
        const answer = d.transport.exchange(io, query, &answer_buf) catch |err| return switch (err) {
            error.NoAnswer => error.NoAnswer,
            error.Canceled => error.Canceled,
        };
        const m = dns.Message.parse(answer) catch return error.NoAnswer;
        if (!(m.answers(id, name, .https) catch false)) return error.NoAnswer;
        switch (m.flags.rcode) {
            .no_error => {},
            .name_error => return error.NoName,
            else => return error.NoAnswer,
        }
        var kept: [max_records]Resolver.Binding.Record = undefined;
        var targets: [max_records][dns.max_name]u8 = undefined;
        var n: usize = 0;
        var alias: ?[]const u8 = null;
        var records = m.records();
        var alias_buf: [dns.max_name]u8 = undefined;
        while (records.next() catch return error.NoAnswer) |r| {
            if (r.kind != .https or r.class != dns.class_in) continue;
            var target_buf: [dns.max_name]u8 = undefined;
            const s = dns.Service.parse(r, &target_buf) catch continue;
            if (s.priority == 0) {
                @memcpy(alias_buf[0..s.target.len], s.target);
                alias = alias_buf[0..s.target.len];
                continue;
            }
            if (!s.usable() or n == max_records) continue;
            // A target of "." is the record's own name (§2.5.2).
            const target = if (s.target.len == 0) name else s.target;
            @memcpy(targets[n][0..target.len], target);
            // In order of priority; equal ones in the answer's order.
            var at = n;
            while (at > 0 and kept[at - 1].service.priority > s.priority) : (at -= 1) kept[at] = kept[at - 1];
            kept[at] = .{ .target = targets[n][0..target.len], .service = s };
            n += 1;
        }
        // RFC 9460 §2.4.2: ServiceMode records beside an alias are ignored.
        if (n != 0 and alias == null) return try Resolver.Binding.init(gpa, kept[0..n]);
        // An alias to the root, or to nowhere new, means no service.
        const next = alias orelse return null;
        if (next.len == 0 or std.ascii.eqlIgnoreCase(next, name)) return null;
        @memcpy(name_buf[0..next.len], next);
        name = name_buf[0..next.len];
    }
    return null;
}

fn serviceFn(io: Io, context: ?*anyopaque, gpa: Allocator, name: []const u8) Resolver.ServiceError!?Resolver.Binding {
    const d: *const Dns = @ptrCast(@alignCast(context.?)); // safe: `resolver` passes a Dns
    return d.https(io, gpa, name) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        // RFC 9460 §3: records that cannot be had are none.
        error.InvalidName, error.NoName, error.NoAnswer => null,
    };
}

/// How many AliasMode records `https` follows.
pub const max_aliases = 8;

/// The most ServiceMode records `https` keeps for one name.
pub const max_records = 16;

/// The configured name servers, asked over UDP and over TCP when an answer
/// is truncated: each in turn, `attempts` rounds, each wait `timeout`.
pub const Stub = struct {
    servers: []const IpAddress,
    timeout: Duration = .literal("5s"),
    attempts: u8 = 2,
    /// Start each query at the next server in turn.
    rotate: bool = false,
    /// Private: the next server to start at, under `rotate`.
    turn: std.atomic.Value(u32) = .init(0),
    /// Private: what keeps each wait's deadline.
    deadlines: reactor.net.Deadlines,
    unenforced: std.atomic.Value(u64) = .init(0),

    /// A stub asking `servers`, each on port 53 unless it names another.
    pub fn init(servers: []const IpAddress, options: Options) Stub {
        return .{
            .servers = servers,
            .timeout = options.timeout,
            .attempts = options.attempts,
            .rotate = options.rotate,
            .deadlines = .init(span.toIo(options.timeout)),
        };
    }

    pub const Options = struct {
        timeout: Duration = .literal("5s"),
        attempts: u8 = 2,
        rotate: bool = false,
    };

    /// The options `config` names.
    pub fn optionsOf(config: *const dns.Config) Options {
        return .{
            .timeout = config.timeout,
            .attempts = config.attempts,
            .rotate = config.rotate,
        };
    }

    pub fn deinit(s: *Stub, io: Io) void {
        s.deadlines.deinit(io);
        s.* = undefined;
    }

    pub fn transport(s: *Stub) Transport {
        return .{ .context = s, .exchangeFn = exchange };
    }

    fn keeper(s: *Stub) Timed.Keeper {
        return .{ .deadlines = &s.deadlines, .unenforced = &s.unenforced };
    }

    fn exchange(io: Io, context: ?*anyopaque, query: []const u8, answer: []u8) ExchangeError![]u8 {
        const s: *Stub = @ptrCast(@alignCast(context.?)); // safe: `transport` passes a Stub
        if (s.servers.len == 0) return error.NoAnswer;
        const first: usize = if (s.rotate) s.turn.fetchAdd(1, .monotonic) % s.servers.len else 0;
        for (0..s.attempts) |_| for (0..s.servers.len) |i| {
            const server = s.servers[(first + i) % s.servers.len];
            const got = s.overUdp(io, server, query, answer) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Failed => continue,
            };
            if (!(dns.Message.parse(got) catch continue).flags.truncated) return got;
            return s.overTcp(io, server, query, answer) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Failed => continue,
            };
        };
        return error.NoAnswer;
    }

    const TryError = error{ Failed, Canceled };

    /// The answer to `query` from `server` over UDP: a datagram from that
    /// address with the query's id and question, waited for until the
    /// timeout; others are dropped.
    fn overUdp(s: *Stub, io: Io, server: IpAddress, query: []const u8, answer: []u8) TryError![]u8 {
        const any: IpAddress = switch (server) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = any.bind(io, .{ .mode = .dgram }) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            else => error.Failed,
        };
        defer socket.close(io);
        socket.send(io, &server, query) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            else => error.Failed,
        };
        var timed: Timed = .init(socket.handle);
        defer timed.deinit(io, s.keeper());
        const deadline = Io.Clock.awake.now(io).addDuration(span.toIo(s.timeout));
        while (true) {
            var message: Io.net.IncomingMessage = .init;
            const result = timed.perform(io, s.keeper(), .{ .net_receive = .{
                .socket_handle = socket.handle,
                .message_buffer = (&message)[0..1],
                .data_buffer = answer,
                .flags = .{},
            } }, deadline) catch |err| return switch (err) {
                error.TimedOut => error.Failed,
                error.Canceled => error.Canceled,
            };
            const maybe_err, const count = result.net_receive;
            if (maybe_err != null or count != 1) return error.Failed;
            if (!message.from.eql(&server) or message.flags.trunc) continue;
            if (sameQuestion(query, message.data)) return message.data;
        }
    }

    /// The answer to `query` from `server` over TCP, each message after its
    /// two-byte length.
    fn overTcp(s: *Stub, io: Io, server: IpAddress, query: []const u8, answer: []u8) TryError![]u8 {
        const deadline = Io.Clock.awake.now(io).addDuration(span.toIo(s.timeout));
        const connected = reactor.net.connect(io, &server, .{ .mode = .stream, .timeout = .{ .deadline = .{ .raw = deadline, .clock = .awake } } }) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            else => error.Failed,
        };
        const stream = connected.stream;
        defer stream.close(io);
        var timed: Timed = .init(stream.socket.handle);
        defer timed.deinit(io, s.keeper());
        var length: [2]u8 = undefined;
        std.mem.writeInt(u16, &length, @intCast(query.len), .big); // safe: a query is far below 64 KiB
        const parts = [_][]const u8{ &length, query };
        var sent: usize = 0;
        const total = query.len + 2;
        while (sent < total) {
            var rest: [2][]const u8 = undefined;
            var n: usize = 0;
            var skip = sent;
            for (parts) |p| {
                if (skip >= p.len) {
                    skip -= p.len;
                    continue;
                }
                rest[n] = p[skip..];
                skip = 0;
                n += 1;
            }
            const result = timed.perform(io, s.keeper(), .{ .net_write = .{ .socket_handle = stream.socket.handle, .data = rest[0..n] } }, deadline) catch |err| return switch (err) {
                error.TimedOut => error.Failed,
                error.Canceled => error.Canceled,
            };
            sent += result.net_write catch return error.Failed;
        }
        try s.readExact(io, &timed, stream, &length, deadline);
        const len = std.mem.readInt(u16, &length, .big);
        if (len > answer.len) return error.Failed;
        try s.readExact(io, &timed, stream, answer[0..len], deadline);
        if (!sameQuestion(query, answer[0..len])) return error.Failed;
        return answer[0..len];
    }

    fn readExact(s: *Stub, io: Io, timed: *Timed, stream: Io.net.Stream, into: []u8, deadline: Io.Timestamp) TryError!void {
        var got: usize = 0;
        while (got < into.len) {
            var data = [_][]u8{into[got..]};
            const result = timed.perform(io, s.keeper(), .{ .net_read = .{ .socket_handle = stream.socket.handle, .data = &data } }, deadline) catch |err| return switch (err) {
                error.TimedOut => error.Failed,
                error.Canceled => error.Canceled,
            };
            const n = (result.net_read catch return error.Failed).data_len;
            if (n == 0) return error.Failed;
            got += n;
        }
    }
};

/// Whether `answer` is a response to `query`: its id, and its question
/// section the query's, byte for byte.
pub fn sameQuestion(query: []const u8, answer: []const u8) bool {
    const q = dns.Message.parse(query) catch return false;
    const a = dns.Message.parse(answer) catch return false;
    if (q.id != a.id or !a.flags.response or a.questions != 1) return false;
    const q_section = query[q.question_at..q.answers_at];
    const a_section = answer[a.question_at..a.answers_at];
    return std.ascii.eqlIgnoreCase(q_section, a_section);
}

/// The system's resolver configuration: `/etc/resolv.conf` on POSIX
/// systems, and the DNS servers of the adapters that are up on Windows,
/// held here with the text it was read from.
pub const System = struct {
    config: dns.Config = .{},
    servers: [dns.Config.max_servers]IpAddress = undefined,
    server_count: u8 = 0,
    /// Private: the text the configuration's slices point into, or the
    /// system's adapter records on Windows.
    text: [16 << 10]u8 align(8) = undefined,

    pub fn serverList(sys: *const System) []const IpAddress {
        return sys.servers[0..sys.server_count];
    }

    /// Why the configuration could not be read.
    pub const LoadError = error{ ConfigurationUnreadable, Canceled };

    /// Read the system's configuration into `sys`, which must stay where
    /// it is while it is used.
    pub fn load(sys: *System, io: Io) LoadError!void {
        sys.* = .{};
        if (@import("builtin").os.tag == .windows) {
            const n = windows_dns.load(&sys.servers, &sys.text) orelse return error.ConfigurationUnreadable;
            sys.server_count = @intCast(n); // safe: at most three servers
            return;
        }
        const text = Io.Dir.cwd().readFile(io, "/etc/resolv.conf", &sys.text) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            // No file: the C library asks the local host.
            error.FileNotFound => sys.fromText(io, "nameserver 127.0.0.1\n"),
            else => error.ConfigurationUnreadable,
        };
        sys.fromText(io, text);
    }

    fn fromText(sys: *System, _: Io, text: []const u8) void {
        sys.config = .parse(text);
        for (sys.config.serverList()) |server| {
            const address = reactor.net.literal(server, 53) orelse continue;
            sys.servers[sys.server_count] = address;
            sys.server_count += 1;
        }
    }
};

const windows_dns = @import("dns/windows.zig");

test "a stub asks a server over UDP, and over TCP when the answer is truncated" {
    const testing = std.testing;
    const io = @import("../testing/io.zig").io();
    var fake: FakeServer = undefined;
    try fake.start(io);
    defer fake.stop(io);
    const servers = [_]IpAddress{fake.address};
    var stub: Stub = .init(&servers, .{ .timeout = .literal("2s"), .attempts = 1 });
    defer stub.deinit(io);
    const d: Dns = .{ .transport = stub.transport() };
    const r = d.resolver();
    var out: [8]IpAddress = undefined;
    const got = try r.lookup(io, "small.test", 443, null, &out);
    try testing.expectEqual(2, got.len);
    try testing.expect(got[0] == .ip6);
    try testing.expectEqual(443, got[1].getPort());
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &got[1].ip4.bytes);
    // Truncated over UDP: the whole answer over TCP, through a CNAME.
    const big = try r.lookup(io, "big.test", 80, .ip4, &out);
    try testing.expectEqual(3, big.len);
    try testing.expectError(error.NameNotResolved, r.lookup(io, "missing.test", 80, null, &out));
    var binding = (try d.https(io, testing.allocator, "small.test")).?;
    defer binding.deinit(testing.allocator);
    try testing.expectEqual(1, binding.records.len);
    const service = binding.records[0].service;
    // The record names no target: its own name is.
    try testing.expectEqualStrings("small.test", binding.records[0].target);
    try testing.expectEqual(1, service.priority);
    var protocols = service.alpn();
    try testing.expectEqualStrings("h2", (try protocols.next()).?);
    try testing.expectEqual(8443, service.port().?);
}

test "a stub canceled at its socket returns error.Canceled, not the next server's answer" {
    const testing = std.testing;
    const shakedown = @import("shakedown");
    const base = @import("../testing/io.zig").io();
    var fake: FakeServer = undefined;
    try fake.start(base);
    defer fake.stop(base);
    // The same server twice: a failure moves on to the second, a cancelation ends the query.
    const servers = [_]IpAddress{ fake.address, fake.address };
    var stub: Stub = .init(&servers, .{ .timeout = .literal("2s"), .attempts = 1 });
    defer stub.deinit(base);
    var query_buf: [dns.max_name + 64]u8 = undefined;
    const query = try dns.writeQuery(&query_buf, 7, "small.test", .a);
    var answer: [dns.max_message]u8 = undefined;
    for ([_]shakedown.IoPlan.Entry{
        .{ .at = .{ .nth = .{ .call = .netBindIp, .n = 1 } }, .fault = .cancel },
        .{ .at = .{ .nth = .{ .call = .net_send, .n = 1 } }, .fault = .cancel },
    }) |entry| {
        const fio = try shakedown.FaultIo.init(testing.allocator, base, .{ .plan = &.{entry} });
        defer fio.deinit();
        try testing.expectError(error.Canceled, stub.transport().exchange(fio.io(), query, &answer));
    }
}

test "search domains are tried as resolv.conf orders them" {
    const testing = std.testing;
    const io = @import("../testing/io.zig").io();
    var fake: FakeServer = undefined;
    try fake.start(io);
    defer fake.stop(io);
    const servers = [_]IpAddress{fake.address};
    var stub: Stub = .init(&servers, .{ .timeout = .literal("2s"), .attempts = 1 });
    defer stub.deinit(io);
    const d: Dns = .{ .transport = stub.transport(), .config = .parse("search nowhere.test test\n") };
    var out: [8]IpAddress = undefined;
    const got = try d.resolver().lookup(io, "small", 80, .ip4, &out);
    try testing.expectEqual(1, got.len);
}

test "the system's configuration is read: its servers, at most three" {
    const io = @import("../testing/io.zig").io();
    var sys: System = undefined;
    sys.load(io) catch |err| switch (err) {
        // A machine may keep no configuration where it is looked for.
        error.ConfigurationUnreadable => return error.SkipZigTest,
        error.Canceled => return err,
    };
    try std.testing.expect(sys.server_count <= dns.Config.max_servers);
    for (sys.serverList()) |server| try std.testing.expectEqual(53, server.getPort());
}

/// A name server on loopback for the tests: `small.test` has an A and an
/// AAAA record and an HTTPS record; `big.test` is a CNAME to `many.test`,
/// whose three A records come truncated over UDP and whole over TCP; any
/// other name does not exist.
const FakeServer = struct {
    udp: Io.net.Socket,
    tcp: Io.net.Server,
    address: IpAddress,
    udp_task: Io.Future(void),
    tcp_task: Io.Future(void),

    fn start(f: *FakeServer, io: Io) !void {
        const loopback = try IpAddress.parse("127.0.0.1", 0);
        // UDP and TCP on one port: the port the system gives the UDP socket
        // may be taken for TCP (another process's connection), so another
        // is asked for until both are free. The listener asks for no address
        // reuse: on Windows a reusing bind over a port another socket holds
        // is refused as access denied, which std reports as Unexpected, where
        // a plain one is AddressInUse.
        var tries: u8 = 0;
        while (true) : (tries += 1) {
            f.udp = try loopback.bind(io, .{ .mode = .dgram });
            f.address = f.udp.address;
            f.tcp = f.address.listen(io, .{}) catch |err| switch (err) {
                error.AddressInUse => {
                    f.udp.close(io);
                    if (tries == 16) return err;
                    continue;
                },
                else => |e| {
                    f.udp.close(io);
                    return e;
                },
            };
            break;
        }
        f.udp_task = io.concurrent(serveUdp, .{ f, io }) catch return error.SkipZigTest;
        f.tcp_task = io.concurrent(serveTcp, .{ f, io }) catch return error.SkipZigTest;
    }

    fn stop(f: *FakeServer, io: Io) void {
        f.udp_task.cancel(io);
        f.tcp_task.cancel(io);
        f.udp.close(io);
        f.tcp.deinit(io);
    }

    fn serveUdp(f: *FakeServer, io: Io) void {
        var buf: [512]u8 = undefined;
        var out: [dns.max_message]u8 = undefined;
        while (true) {
            const message = f.udp.receive(io, &buf) catch return;
            const reply = answer(message.data, &out, true) orelse continue;
            f.udp.send(io, &message.from, reply) catch return;
        }
    }

    fn serveTcp(f: *FakeServer, io: Io) void {
        while (true) {
            const stream = f.tcp.accept(io) catch return;
            defer stream.close(io);
            var rbuf: [1024]u8 = undefined;
            var r = stream.reader(io, &rbuf);
            var wbuf: [4096]u8 = undefined;
            var w = stream.writer(io, &wbuf);
            const len = r.interface.takeInt(u16, .big) catch continue;
            const query = r.interface.take(len) catch continue;
            var out: [dns.max_message]u8 = undefined;
            const reply = answer(query, &out, false) orelse continue;
            w.interface.writeInt(u16, @intCast(reply.len), .big) catch continue; // safe: the fake's answers are small
            w.interface.writeAll(reply) catch continue;
            w.interface.flush() catch continue;
        }
    }

    /// The answer to `query`: its header and question, then the records.
    fn answer(query: []const u8, out: []u8, udp: bool) ?[]u8 {
        const q = dns.Message.parse(query) catch return null;
        var name_buf: [dns.max_name]u8 = undefined;
        const name = dns.readName(query, q.question_at, &name_buf) catch return null;
        const kind = std.mem.readInt(u16, query[q.answers_at - 4 ..][0..2], .big);
        @memcpy(out[0..q.answers_at], query[0..q.answers_at]);
        var flags: u16 = 0x8180;
        var records: [4][]const u8 = undefined;
        var n: usize = 0;
        // Each record's owner is the question's name, by a pointer to it.
        if (std.mem.eql(u8, name, "small.test") or std.mem.eql(u8, name, "small.nowhere.test")) {
            if (std.mem.eql(u8, name, "small.nowhere.test")) {
                flags |= 3;
            } else switch (kind) {
                1 => {
                    records[0] = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01";
                    n = 1;
                },
                28 => {
                    records[0] = "\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
                    n = 1;
                },
                65 => {
                    records[0] = "\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x3c\x00\x10\x00\x01\x00\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x20\xfb";
                    n = 1;
                },
                else => {},
            }
        } else if (std.mem.eql(u8, name, "big.test")) {
            if (udp) {
                flags |= 0x0200;
            } else {
                // big.test CNAME many.test, then many.test's three A records.
                records[0] = "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x07\x04many\xc0\x10";
                n = 1;
                if (kind == 1) for (1..4) |i| {
                    records[i] = switch (i) {
                        1 => "\xc0\x26\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x00\x00\x01",
                        2 => "\xc0\x26\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x00\x00\x02",
                        else => "\xc0\x26\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x00\x00\x03",
                    };
                    n += 1;
                };
            }
        } else flags |= 3;
        std.mem.writeInt(u16, out[2..4], flags, .big);
        std.mem.writeInt(u16, out[6..8], @intCast(n), .big); // safe: at most four records
        std.mem.writeInt(u16, out[8..10], 0, .big);
        std.mem.writeInt(u16, out[10..12], 0, .big);
        var at = q.answers_at;
        for (records[0..n]) |r| {
            @memcpy(out[at..][0..r.len], r);
            at += r.len;
        }
        return out[0..at];
    }
};

test "service answers are kept for their time, none included, and a static name has none" {
    const testing = std.testing;
    const shakedown = @import("shakedown");
    const test_io = @import("../testing/io.zig");
    const zone = @import("../testing/zone.zig");
    const Cache = Resolver.Cache;
    const Static = Resolver.Static;
    var clock: shakedown.Clock = .init(test_io.io(), .{});
    const io = clock.io();
    const gpa = testing.allocator;
    const entries = [_]zone.Entry{.{ .name = "svc.example", .https = &.{ .{ .priority = 2, .target = "b.example" }, .{ .priority = 1 } } }};
    var z: zone.Zone = .{ .entries = &entries };
    const d: Dns = .{ .transport = z.transport() };
    var cache: Cache = .init(gpa, d.resolver(), .{ .ttl = .literal("60s") });
    defer cache.deinit(io);
    const r = cache.resolver();
    for (0..2) |_| {
        var b = (try r.service(io, gpa, "svc.example", 443)).?;
        defer b.deinit(gpa);
        // The most preferred first; "." is the record's own name.
        try testing.expectEqual(2, b.records.len);
        try testing.expectEqualStrings("svc.example", b.records[0].target);
        try testing.expectEqualStrings("b.example", b.records[1].target);
        try testing.expectEqual(null, try r.service(io, gpa, "none.example", 443));
    }
    // One question each for the two names, the second round from the cache.
    try testing.expectEqual(@as(u32, 2), z.asked.load(.monotonic));
    clock.advance(.fromSeconds(61));
    var again = (try r.service(io, gpa, "svc.example", 443)).?;
    again.deinit(gpa);
    try testing.expectEqual(@as(u32, 3), z.asked.load(.monotonic));
    // A name a static entry answers is reached at its addresses alone.
    const pinned = [_]Static.Entry{.{ .host = "svc.example", .addresses = &.{.{ .ip4 = .loopback(0) }} }};
    const s: Static = .{ .entries = &pinned, .fallback = d.resolver() };
    try testing.expectEqual(null, try s.resolver().service(io, gpa, "svc.example", 8443));
    try testing.expect(s.resolver().serviceFn != null);
    try testing.expectEqual(null, try Resolver.system.service(io, gpa, "svc.example", 443));
}
