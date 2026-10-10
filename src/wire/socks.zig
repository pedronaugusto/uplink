//! SOCKS CONNECT framing (SOCKS4, SOCKS4a, SOCKS5 of RFC 1928 with the
//! user and password of RFC 1929). Reads consume exactly one reply; bytes of the tunneled
//! protocol stay put.

const std = @import("std");
const Io = std.Io;

/// The SOCKS variants: 4a and 5h send the name for the proxy to look up.
pub const Version = enum { socks4, socks4a, socks5, socks5h };

/// Failures a SOCKS peer reports, or malformed negotiation on the wire.
pub const Error = error{
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyHostUnreachable,
    ProxyNetworkUnreachable,
    ProxyCommandUnsupported,
    ProxyAddressUnsupported,
    ProxyTtlExpired,
    SocksProtocolError,
};

/// The user and password a SOCKS proxy is answered with.
pub const Credential = struct { user: []const u8, password: []const u8 };

/// Errors from `reply`.
pub const ReplyError = error{
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyHostUnreachable,
    ProxyNetworkUnreachable,
    ProxyCommandUnsupported,
    ProxyAddressUnsupported,
    ProxyTtlExpired,
    SocksProtocolError,
    ReadFailed,
    EndOfStream,
};
/// Errors from `authenticate`.
pub const AuthenticateError = error{
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyHostUnreachable,
    ProxyNetworkUnreachable,
    ProxyCommandUnsupported,
    ProxyAddressUnsupported,
    ProxyTtlExpired,
    SocksProtocolError,
    ReadFailed,
    EndOfStream,
    WriteFailed,
};
/// Errors from `request`.
pub const RequestError = error{
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyHostUnreachable,
    ProxyNetworkUnreachable,
    ProxyCommandUnsupported,
    ProxyAddressUnsupported,
    ProxyTtlExpired,
    SocksProtocolError,
    WriteFailed,
};

/// Finish a SOCKS4/4a or SOCKS5 CONNECT reply, including its bound address.
pub fn reply(r: *Io.Reader, version: Version, status: ?*u16) ReplyError!void {
    if (version == .socks4 or version == .socks4a) {
        var bytes: [8]u8 = undefined;
        try r.readSliceAll(&bytes);
        if (status) |s| s.* = bytes[1];
        if (bytes[0] != 0) return error.SocksProtocolError;
        return switch (bytes[1]) {
            90 => {},
            91 => error.ProxyRefused,
            92, 93 => error.ProxyAuthenticationRequired,
            else => error.SocksProtocolError,
        };
    }
    var head: [4]u8 = undefined;
    try r.readSliceAll(&head);
    if (status) |s| s.* = head[1];
    if (head[0] != 5 or head[2] != 0) return error.SocksProtocolError;
    if (head[1] != 0) return switch (head[1]) {
        1, 2, 5 => error.ProxyRefused,
        3 => error.ProxyNetworkUnreachable,
        4 => error.ProxyHostUnreachable,
        6 => error.ProxyTtlExpired,
        7 => error.ProxyCommandUnsupported,
        8 => error.ProxyAddressUnsupported,
        else => error.SocksProtocolError,
    };
    const len: usize = switch (head[3]) {
        1 => 4,
        4 => 16,
        3 => try r.takeByte(),
        else => return error.SocksProtocolError,
    };
    var rest: [257]u8 = undefined;
    try r.readSliceAll(rest[0 .. len + 2]);
}

/// Authenticate SOCKS5, offering no-auth and, when supplied, RFC 1929.
/// The RFC 1929 reply version is ignored; the status alone decides it.
pub fn authenticate(r: *Io.Reader, w: *Io.Writer, credential: ?Credential) AuthenticateError!void {
    try w.writeAll(if (credential != null) &.{ 5, 2, 0, 2 } else &.{ 5, 1, 0 });
    try w.flush();
    var answer: [2]u8 = undefined;
    try r.readSliceAll(&answer);
    if (answer[0] != 5) return error.SocksProtocolError;
    switch (answer[1]) {
        0 => return,
        2 => {},
        255 => return error.ProxyAuthenticationRequired,
        else => return error.ProxyAuthMethodUnsupported,
    }
    const c = credential orelse return error.ProxyAuthenticationRequired;
    if (c.user.len > 255 or c.password.len > 255) return error.ProxyAuthenticationRequired;
    try w.writeAll(&.{ 1, @intCast(c.user.len) });
    try w.writeAll(c.user);
    try w.writeByte(@intCast(c.password.len));
    try w.writeAll(c.password);
    try w.flush();
    try r.readSliceAll(&answer);
    if (answer[1] != 0) return error.ProxyAuthenticationRequired;
}

/// Write a CONNECT request. `address` is the local lookup for 4/5, or a
/// literal for 5h; 4a always sends the name behind its 0.0.0.1 marker.
pub fn request(w: *Io.Writer, version: Version, host: []const u8, port: u16, address: ?Io.net.IpAddress, credential: ?Credential) RequestError!void {
    const port_bytes = std.mem.toBytes(std.mem.nativeToBig(u16, port));
    if (version == .socks4 or version == .socks4a) {
        if (std.mem.findScalar(u8, host, ':') != null) return error.ProxyAddressUnsupported;
        const user = if (credential) |c| c.user else "";
        if (user.len > 255 or std.mem.findScalar(u8, user, 0) != null) return error.ProxyAuthenticationRequired;
        if (version == .socks4a and (host.len == 0 or host.len > 254 or std.mem.findScalar(u8, host, 0) != null)) return error.ProxyAddressUnsupported;
        try w.writeAll(&.{ 4, 1 });
        try w.writeAll(&port_bytes);
        if (version == .socks4a) {
            try w.writeAll(&.{ 0, 0, 0, 1 });
        } else switch (address orelse return error.ProxyHostUnreachable) {
            .ip4 => |a| try w.writeAll(&a.bytes),
            .ip6 => return error.ProxyAddressUnsupported,
        }
        try w.writeAll(user);
        try w.writeByte(0);
        if (version == .socks4a) {
            try w.writeAll(host);
            try w.writeByte(0);
        }
    } else {
        try w.writeAll(&.{ 5, 1, 0 });
        if (address) |a| switch (a) {
            .ip4 => |v| {
                try w.writeByte(1);
                try w.writeAll(&v.bytes);
            },
            .ip6 => |v| {
                try w.writeByte(4);
                try w.writeAll(&v.bytes);
            },
        } else {
            if (version != .socks5h) return error.ProxyHostUnreachable;
            if (host.len == 0 or host.len > 255 or std.mem.findScalar(u8, host, 0) != null) return error.ProxyAddressUnsupported;
            try w.writeAll(&.{ 3, @intCast(host.len) });
            try w.writeAll(host);
        }
        try w.writeAll(&port_bytes);
    }
    try w.flush();
}

const testing = std.testing;

test "SOCKS replies consume the whole bound address and leave the tunnel's bytes" {
    for ([_][]const u8{
        &.{ 5, 0, 0, 1, 127, 0, 0, 1, 0, 80, 42 },
        &.{ 5, 0, 0, 3, 3, 'a', 'b', 'c', 0, 80, 42 },
        &.{ 5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80, 42 },
    }) |bytes| {
        var r: Io.Reader = .fixed(bytes);
        try reply(&r, .socks5, null);
        try testing.expectEqual(@as(u8, 42), try r.takeByte());
        for (0..bytes.len - 1) |len| {
            var short: Io.Reader = .fixed(bytes[0..len]);
            try testing.expectError(error.EndOfStream, reply(&short, .socks5, null));
        }
    }
    var r: Io.Reader = .fixed(&.{ 0, 90, 0, 80, 127, 0, 0, 1, 42 });
    try reply(&r, .socks4, null);
    try testing.expectEqual(@as(u8, 42), try r.takeByte());
}

test "SOCKS refusals have names and preserve the peer's reply code" {
    const errors = [_]Error{ error.ProxyRefused, error.ProxyRefused, error.ProxyNetworkUnreachable, error.ProxyHostUnreachable, error.ProxyRefused, error.ProxyTtlExpired, error.ProxyCommandUnsupported, error.ProxyAddressUnsupported };
    for (errors, 1..) |err, code| {
        var r: Io.Reader = .fixed(&.{ 5, @intCast(code), 0, 1 });
        var status: u16 = 0;
        try testing.expectError(err, reply(&r, .socks5, &status));
        try testing.expectEqual(code, status);
    }
    for ([_][]const u8{ &.{ 4, 0, 0, 1 }, &.{ 5, 0, 1, 1 }, &.{ 5, 0, 0, 2 } }) |bytes| {
        var r: Io.Reader = .fixed(bytes);
        try testing.expectError(error.SocksProtocolError, reply(&r, .socks5, null));
    }
}

test "SOCKS framing distinguishes local addresses from proxy-resolved names" {
    var buffer: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    try request(&w, .socks5h, "remote.invalid", 443, null, null);
    try testing.expectEqualSlices(u8, &.{ 5, 1, 0, 3, 14, 'r', 'e', 'm', 'o', 't', 'e', '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd', 1, 187 }, w.buffered());
    w.end = 0;
    try request(&w, .socks5, "localhost", 80, try Io.net.IpAddress.parse("127.0.0.1", 80), null);
    try testing.expectEqualSlices(u8, &.{ 5, 1, 0, 1, 127, 0, 0, 1, 0, 80 }, w.buffered());
    w.end = 0;
    try request(&w, .socks4a, "remote.invalid", 80, null, .{ .user = "u", .password = "ignored" });
    try testing.expectEqualSlices(u8, &.{ 4, 1, 0, 80, 0, 0, 0, 1, 'u', 0, 'r', 'e', 'm', 'o', 't', 'e', '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0 }, w.buffered());
    try testing.expectError(error.ProxyAddressUnsupported, request(&w, .socks4, "::1", 80, try Io.net.IpAddress.parse("::1", 80), null));
}

test "SOCKS authentication follows the selected method and bounds credential lengths" {
    var buffer: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var r: Io.Reader = .fixed(&.{ 5, 2, 1, 0 });
    try authenticate(&r, &w, .{ .user = "user", .password = "pass" });
    try testing.expectEqualSlices(u8, &.{ 5, 2, 0, 2, 1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's' }, w.buffered());
    for ([_][]const u8{ &.{ 5, 255 }, &.{ 5, 2, 1, 1 } }) |bytes| {
        r = .fixed(bytes);
        try testing.expectError(error.ProxyAuthenticationRequired, authenticate(&r, &w, .{ .user = "user", .password = "pass" }));
    }
    r = .fixed(&.{ 5, 2 });
    try testing.expectError(error.ProxyAuthenticationRequired, authenticate(&r, &w, .{ .user = &@as([256]u8, @splat('u')), .password = "pass" }));
    r = .fixed(&.{ 5, 1 });
    try testing.expectError(error.ProxyAuthMethodUnsupported, authenticate(&r, &w, null));
}

test "fuzz: a SOCKS reply is consumed exactly or refused by name" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) !void {
            var scratch: [1024]u8 = undefined;
            const bytes = scratch[0..smith.slice(&scratch)];
            for ([_]Version{ .socks4, .socks5 }) |version| {
                var r: Io.Reader = .fixed(bytes);
                reply(&r, version, null) catch continue;
                try testing.expect(r.seek <= bytes.len);
            }
        }
    }.run, .{ .corpus = &.{ &.{ 0, 90, 0, 0, 0, 0, 0, 0 }, &.{ 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, &.{ 5, 0, 0, 3, 1, 'a', 0, 0 }, &.{ 5, 4, 0, 1 } } });
}
