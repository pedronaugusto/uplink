//! Source layers, lowest first. Every production source has one explicit place.
const gantry = @import("gantry");

pub const layers: []const gantry.rules.Layer = &.{
    .{ .name = "wire grammar", .patterns = &.{
        "src/wire/fields.zig",
        "src/wire/version.zig",
        "src/wire/date.zig",
        "src/wire/cache.zig",
        "src/wire/form.zig",
        "src/wire/sse.zig",
        "src/wire/range.zig",
        "src/wire/netrc.zig",
        "src/wire/dns.zig",
        "src/wire/ws.zig",
        "src/wire/hpack/huffman_codes.zig",
        "src/wire/hpack.zig",
        "src/wire/h2/frame.zig",
    } },
    .{ .name = "wire codecs", .patterns = &.{
        "src/wire/Method.zig",
        "src/wire/coding.zig",
        "src/wire/cookie.zig",
        "src/wire/multipart.zig",
        "src/wire/socks.zig",
        "src/wire/url.zig",
    } },
    .{ .name = "wire messages", .patterns = &.{
        "src/wire/h1.zig",
        "src/wire/auth.zig",
        "src/wire/sigv4.zig",
    } },
    .{ .name = "wire connections", .patterns = &.{
        "src/wire/h2/Connection.zig",
        "src/wire/h2/message.zig",
        "src/wire/h2.zig",
    } },
    .{ .name = "wire", .patterns = &.{
        "src/wire.zig",
    } },
    .{ .name = "span", .patterns = &.{
        "src/span.zig",
    } },
    .{ .name = "sync", .patterns = &.{
        "src/sync.zig",
    } },
    .{ .name = "erased", .patterns = &.{
        "src/erased.zig",
    } },
    .{ .name = "place", .patterns = &.{
        "src/place.zig",
    } },
    .{ .name = "tls", .patterns = &.{
        "src/tls.zig",
    } },
    .{ .name = "net system", .patterns = &.{
        "src/net/sys.zig",
        "src/net/stream.zig",
        "src/net/Timed.zig",
        "src/net/dns/windows.zig",
    } },
    .{ .name = "net resolver", .patterns = &.{
        "src/net/Resolver.zig",
    } },
    .{ .name = "net dns", .patterns = &.{
        "src/net/Dns.zig",
    } },
    .{ .name = "net dial", .patterns = &.{
        "src/net/dial.zig",
    } },
    .{ .name = "net", .patterns = &.{
        "src/net.zig",
    } },
    .{ .name = "transport clock", .patterns = &.{
        "src/transport/awake.zig",
    } },
    .{ .name = "transport values", .patterns = &.{
        "src/transport/Proxy.zig",
        "src/transport/Diagnostics.zig",
        "src/transport/BufferPool.zig",
        "src/transport/Observer.zig",
        "src/transport/Body.zig",
        "src/transport/Head.zig",
        "src/transport/Outbox.zig",
    } },
    .{ .name = "coding", .patterns = &.{
        "src/coding/ZstdBuffer.zig",
        "src/coding/Decoder.zig",
        "src/coding/Encoder.zig",
        "src/coding.zig",
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
    .{ .name = "transport multiplexed", .patterns = &.{
        "src/transport/H2.zig",
    } },
    .{ .name = "transport", .patterns = &.{
        "src/transport.zig",
    } },
    .{ .name = "pool", .patterns = &.{
        "src/pool/Pool.zig",
        "src/pool.zig",
    } },
    .{ .name = "client values", .patterns = &.{
        "src/client/policy.zig",
        "src/client/Credentials.zig",
        "src/client/Prepare.zig",
    } },
    .{ .name = "client request", .patterns = &.{
        "src/client/Request.zig",
        "src/client/CookieJar.zig",
        "src/client/Cache.zig",
        "src/client/OriginAuth.zig",
        "src/client/Upgraded.zig",
    } },
    .{ .name = "client response", .patterns = &.{
        "src/client/Response.zig",
    } },
    .{ .name = "client shared", .patterns = &.{
        "src/client/Shared.zig",
    } },
    .{ .name = "client exchange", .patterns = &.{
        "src/client/Run.zig",
        "src/client/Outgoing.zig",
        "src/client/Client.zig",
    } },
    .{ .name = "client dns", .patterns = &.{
        "src/client/Doh.zig",
    } },
    .{ .name = "server patterns", .patterns = &.{
        "src/server/Pattern.zig",
    } },
    .{ .name = "server context", .patterns = &.{
        "src/server/Context.zig",
    } },
    .{ .name = "server socket", .patterns = &.{
        "src/server/Socket.zig",
    } },
    .{ .name = "server h2 session", .patterns = &.{
        "src/server/h2/Session.zig",
    } },
    .{ .name = "server exchange", .patterns = &.{
        "src/server/Request.zig",
        "src/server/Response.zig",
    } },
    .{ .name = "server handler", .patterns = &.{
        "src/server/Handler.zig",
    } },
    .{ .name = "server h2", .patterns = &.{
        "src/server/h2/serve.zig",
        "src/server/h2.zig",
    } },
    .{ .name = "server connection", .patterns = &.{
        "src/server/Connection.zig",
    } },
    .{ .name = "server", .patterns = &.{
        "src/server/Server.zig",
    } },
    .{ .name = "server routing", .patterns = &.{
        "src/server/Router.zig",
    } },
    .{ .name = "server comptime routing", .patterns = &.{
        "src/server/routes.zig",
    } },
    .{ .name = "server files", .patterns = &.{
        "src/server/Files.zig",
    } },
    .{ .name = "server namespace", .patterns = &.{
        "src/server.zig",
    } },
    .{ .name = "ws connection", .patterns = &.{
        "src/ws/Conn.zig",
    } },
    .{ .name = "client namespace", .patterns = &.{
        "src/client.zig",
    } },
    .{ .name = "ws", .patterns = &.{
        "src/ws.zig",
    } },
    .{ .name = "public", .patterns = &.{
        "src/uplink.zig",
    } },
};

pub const entries: []const []const u8 = &.{};

pub const modules: []const gantry.NamedModule = &.{
    .{ .name = "uplink.wire", .path = "src/wire.zig", .from = "src/**" },
};

pub const references: []const gantry.rules.ReferenceRule = &.{
    .{ .name = "named dependencies", .unresolved_only = true, .except_targets = &.{
        "aegis",
        "builtin",
        "cloak",
        "warp",
        "xenoglyph",
        "reactor",
        "shakedown",
        "std",
        "test_io",
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

/// Tokens only their owner may spell. No uplink task waits on work started
/// with `io.async` or `Group.async`, which Zig 0.17 no longer promises runs
/// beside its caller: work another task waits on is started with
/// `io.concurrent`, or done inline. Nothing owns them.
pub const owned: []const gantry.rules.TokenRule = &.{
    .{ .name = "no waiting on async work", .tokens = &.{
        "async",
        "groupAsync",
    }, .owners = &.{} },
};
