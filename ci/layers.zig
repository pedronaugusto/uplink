//! Source layers, lowest first. Every production source has one explicit place.
const gantry = @import("gantry");

pub const layers: []const gantry.rules.Layer = &.{
    .{ .name = "wire grammar", .patterns = &.{
        "src/wire/fields.zig",
        "src/wire/version.zig",
    } },
    .{ .name = "wire codecs", .patterns = &.{
        "src/wire/Method.zig",
        "src/wire/coding.zig",
        "src/wire/socks.zig",
        "src/wire/url.zig",
    } },
    .{ .name = "wire messages", .patterns = &.{
        "src/wire/h1.zig",
        "src/wire/auth.zig",
    } },
    .{ .name = "wire", .patterns = &.{
        "src/wire.zig",
    } },
    .{ .name = "tls primitives", .patterns = &.{
        "src/tls/der.zig",
        "src/tls/rsa.zig",
    } },
    .{ .name = "tls keys", .patterns = &.{
        "src/tls/key.zig",
    } },
    .{ .name = "tls credentials", .patterns = &.{
        "src/tls/ClientAuth.zig",
        "src/tls/Trust.zig",
    } },
    .{ .name = "tls handshake", .patterns = &.{
        "src/tls/auth_wire.zig",
    } },
    .{ .name = "tls client", .patterns = &.{
        "src/tls/Client.zig",
    } },
    .{ .name = "tls session", .patterns = &.{
        "src/tls/Session.zig",
    } },
    .{ .name = "tls", .patterns = &.{
        "src/tls.zig",
    } },
    .{ .name = "net system", .patterns = &.{
        "src/net/sys.zig",
    } },
    .{ .name = "net lookup", .patterns = &.{
        "src/net/resolve.zig",
    } },
    .{ .name = "net dial", .patterns = &.{
        "src/net/dial.zig",
    } },
    .{ .name = "net", .patterns = &.{
        "src/net.zig",
    } },
    .{ .name = "transport values", .patterns = &.{
        "src/transport/Proxy.zig",
        "src/transport/Diagnostics.zig",
        "src/transport/BufferPool.zig",
        "src/transport/Timer.zig",
    } },
    .{ .name = "transport shared", .patterns = &.{
        "src/transport/ProxyAuth.zig",
    } },
    .{ .name = "transport context", .patterns = &.{
        "src/transport/Context.zig",
    } },
    .{ .name = "transport connection", .patterns = &.{
        "src/transport/Connection.zig",
    } },
    .{ .name = "transport", .patterns = &.{
        "src/transport.zig",
    } },
    .{ .name = "pool", .patterns = &.{
        "src/pool/Pool.zig",
        "src/pool.zig",
    } },
    .{ .name = "client values", .patterns = &.{
        "src/client/Request.zig",
        "src/client/Body.zig",
    } },
    .{ .name = "client response", .patterns = &.{
        "src/client/Response.zig",
    } },
    .{ .name = "client outgoing", .patterns = &.{
        "src/client/Outgoing.zig",
    } },
    .{ .name = "client", .patterns = &.{
        "src/client/Client.zig",
    } },
    .{ .name = "client namespace", .patterns = &.{
        "src/client.zig",
    } },
    .{ .name = "public", .patterns = &.{
        "src/uplink.zig",
    } },
};

pub const entries: []const []const u8 = &.{};

pub const modules: []const gantry.NamedModule = &.{};

pub const references: []const gantry.rules.ReferenceRule = &.{
    .{ .name = "named dependencies", .unresolved_only = true, .except_targets = &.{
        "builtin",
        "shakedown",
        "std",
        "std_tls_client",
        "uplink",
    } },
    .{ .name = "source siblings", .suffix = ".zig", .relative = true, .except_targets = &.{"src/**"} },
};

pub const required = blk: {
    var count: usize = 0;
    for (layers) |layer| count += layer.patterns.len;
    var paths: [count][]const u8 = undefined;
    var i: usize = 0;
    for (layers) |layer| for (layer.patterns) |path| {
        paths[i] = path;
        i += 1;
    };
    break :blk paths;
};
