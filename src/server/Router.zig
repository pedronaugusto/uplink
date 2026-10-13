//! Routes requests to handlers by pattern, with Go 1.22's semantics
//! (`Pattern`): order-independent, the most specific pattern wins, two that
//! conflict are refused at `add`, `GET` serves `HEAD`, a path that matches
//! only under other methods is a 405 with `Allow`, a path that is not
//! clean is redirected to its clean form, a path that names a subtree
//! without its trailing `/` is redirected to it, and anything else is a
//! 404. Segments are matched with their escapes undone, so `%2F` stays
//! inside its segment; a capture's value has its escapes undone too.
//!
//! The patterns live in a tree of path segments: a node's literal children
//! in sorted order for a binary search, one wildcard child whatever the
//! names patterns give it, and the routes that end there. A match walks
//! it, literal before wildcard before the rest of the path, and backs out
//! of a branch that ends without a route for the method: conflicts having
//! been refused, the first route found is the most specific. A match
//! allocates nothing; a capture's value is unescaped into a buffer of the
//! server's, kept with the request.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const Method = wire.Method;
const Pattern = @import("Pattern.zig");
const Handler = @import("Handler.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");

const Router = @This();

gpa: Allocator,
/// Private: what the patterns, their segments and their copies live in.
arena: std.heap.ArenaAllocator,
/// Private: the tree of patterns with no host.
any_host: Node = .{},
/// Private: a tree per host patterns name.
hosts: std.ArrayList(HostTree) = .empty,
/// Private: every route, for the conflict check.
routes: std.ArrayList(*const Route) = .empty,
/// What a request no pattern matches is handed to; null answers 404.
not_found: ?Handler = null,
/// After `add` refused a pattern as a conflict: the pattern it conflicts
/// with.
conflict: ?[]const u8 = null,

const HostTree = struct { host: []const u8, root: Node };

const Route = struct {
    pattern: Pattern,
    handler: Handler,
};

const Node = struct {
    /// Children by literal segment, sorted.
    literals: std.ArrayList(Child) = .empty,
    wildcard: ?*Node = null,
    /// Routes whose path ends here.
    here: std.ArrayList(*const Route) = .empty,
    /// Routes whose path ends with `{$}` here.
    end: std.ArrayList(*const Route) = .empty,
    /// Routes whose path takes the rest from here.
    rest: std.ArrayList(*const Route) = .empty,

    const Child = struct { text: []const u8, node: *Node };

    fn literal(n: *const Node, escaped: []const u8) ?*Node {
        // Sorted by unescaped text, which an escaped segment is compared
        // to as it is undone: a segment with no escape is found by a binary
        // search, one with escapes by a walk.
        if (std.mem.findScalar(u8, escaped, '%') == null) {
            const i = std.sort.binarySearch(Child, n.literals.items, escaped, struct {
                fn order(key: []const u8, c: Child) std.math.Order {
                    return std.mem.order(u8, key, c.text);
                }
            }.order) orelse return null;
            return n.literals.items[i].node;
        }
        for (n.literals.items) |c| if (Pattern.eqlEscaped(c.text, escaped)) return c.node;
        return null;
    }
};

/// An empty router.
pub fn init(gpa: Allocator) Router {
    return .{ .gpa = gpa, .arena = .init(gpa) };
}

/// Free the tree. Handlers are the caller's.
pub fn deinit(r: *Router) void {
    r.arena.deinit();
    r.* = undefined;
}

/// Why a pattern was not added.
pub const AddError = Pattern.Error || error{
    /// It conflicts with a pattern added before: `conflict` names it.
    Conflict,
    OutOfMemory,
};

/// Route requests `pattern` matches to `target`.
pub fn add(r: *Router, pattern: []const u8, target: Handler) AddError!void {
    const a = r.arena.allocator();
    const text = try a.dupe(u8, pattern);
    const segments = try a.alloc(Pattern.Segment, Pattern.countSegments(text));
    const scratch = try a.alloc(u8, text.len);
    const parsed = try Pattern.parse(text, segments, scratch);
    for (r.routes.items) |other| if (parsed.conflicts(&other.pattern)) {
        r.conflict = other.pattern.text;
        return error.Conflict;
    };
    const route = try a.create(Route);
    route.* = .{ .pattern = parsed, .handler = target };
    try r.routes.append(a, route);
    const root = try r.rootFor(parsed.host);
    var node = root;
    for (parsed.segments) |seg| switch (seg.kind) {
        .literal => node = try r.literalChild(node, seg.text),
        .wildcard => {
            if (node.wildcard == null) {
                const child = try a.create(Node);
                child.* = .{};
                node.wildcard = child;
            }
            node = node.wildcard.?;
        },
        .multi => return node.rest.append(a, route),
        .end => return node.end.append(a, route),
    };
    try node.here.append(a, route);
}

fn rootFor(r: *Router, host: ?[]const u8) Allocator.Error!*Node {
    const h = host orelse return &r.any_host;
    for (r.hosts.items) |*t| if (std.ascii.eqlIgnoreCase(t.host, h)) return &t.root;
    try r.hosts.append(r.arena.allocator(), .{ .host = h, .root = .{} });
    return &r.hosts.items[r.hosts.items.len - 1].root;
}

fn literalChild(r: *Router, node: *Node, text: []const u8) Allocator.Error!*Node {
    const items = node.literals.items;
    const at = std.sort.lowerBound(Node.Child, items, text, struct {
        fn order(key: []const u8, c: Node.Child) std.math.Order {
            return std.mem.order(u8, key, c.text);
        }
    }.order);
    if (at < items.len and std.mem.eql(u8, items[at].text, text)) return items[at].node;
    const a = r.arena.allocator();
    const child = try a.create(Node);
    child.* = .{};
    try node.literals.insert(a, at, .{ .text = text, .node = child });
    return child;
}

/// The methods the patterns matching a path allow, when none allows the
/// request's: for `Allow`.
pub const Allowed = struct {
    methods: [16][]const u8 = undefined,
    len: u8 = 0,
    /// Any method: a pattern with none matched.
    any: bool = false,

    pub fn add(a: *Allowed, method: []const u8) void {
        for (a.methods[0..a.len]) |m| if (std.mem.eql(u8, m, method)) return;
        if (a.len == a.methods.len) return;
        a.methods[a.len] = method;
        a.len += 1;
    }

    /// The methods, sorted, `GET` bringing `HEAD`.
    pub fn sorted(a: *Allowed) []const []const u8 {
        var has_get = false;
        var has_head = false;
        for (a.methods[0..a.len]) |m| {
            has_get = has_get or std.mem.eql(u8, m, "GET");
            has_head = has_head or std.mem.eql(u8, m, "HEAD");
        }
        if (has_get and !has_head) a.add("HEAD");
        std.mem.sort([]const u8, a.methods[0..a.len], {}, struct {
            fn less(_: void, x: []const u8, y: []const u8) bool {
                return std.mem.order(u8, x, y) == .lt;
            }
        }.less);
        return a.methods[0..a.len];
    }
};

/// A route a request matched, and the escaped values its wildcards took,
/// in the pattern's order.
pub const Match = struct {
    route: *const Route,
    values: [Pattern.max_wildcards][]const u8 = undefined,
    len: u8 = 0,

    /// The pattern that matched.
    pub fn pattern(m: *const Match) []const u8 {
        return m.route.pattern.text;
    }
};

/// The route for `method` on `host` (its port left off) and `path` (as
/// sent, escapes in), or null; `allowed` gathers the methods of patterns
/// that matched the path under another method.
pub fn match(r: *const Router, method: Method, host: []const u8, path: []const u8, allowed: *Allowed) ?Match {
    std.debug.assert(path.len != 0);
    std.debug.assert(path[0] == '/');
    const name = hostName(host);
    for (r.hosts.items) |*t| if (std.ascii.eqlIgnoreCase(t.host, name)) {
        var found: Match = undefined;
        if (walk(&t.root, method.name, path[1..], true, &found, allowed)) return found;
    };
    var found: Match = undefined;
    if (walk(&r.any_host, method.name, path[1..], true, &found, allowed)) return found;
    return null;
}

/// A host without its port.
pub fn hostName(host: []const u8) []const u8 {
    if (host.len != 0 and host[0] == '[') {
        const close = std.mem.findScalar(u8, host, ']') orelse return host;
        return host[0 .. close + 1];
    }
    const colon = std.mem.findScalarLast(u8, host, ':') orelse return host;
    return host[0..colon];
}

/// The walk from `node` over `rest`, the path after a `/` when `slash`,
/// or after the end of a segment with nothing following.
fn walk(node: *const Node, method: []const u8, rest: []const u8, slash: bool, found: *Match, allowed: *Allowed) bool {
    if (rest.len == 0) {
        if (!slash) return pick(node.here.items, method, found, allowed);
        // The path ends in `/`: `{$}`, then what takes the rest (nothing).
        if (pick(node.end.items, method, found, allowed)) return true;
        if (pickRest(node.rest.items, method, rest, found, allowed)) return true;
        return false;
    }
    const cut = std.mem.findScalar(u8, rest, '/');
    const segment = rest[0 .. cut orelse rest.len];
    const next = if (cut) |c| rest[c + 1 ..] else "";
    const next_slash = cut != null;
    if (node.literal(segment)) |child| {
        if (walk(child, method, next, next_slash, found, allowed)) return true;
    }
    if (node.wildcard) |child| if (segment.len != 0) {
        if (walk(child, method, next, next_slash, found, allowed)) {
            // Captures are gathered as the walk returns: shift this one in
            // front of those deeper.
            insertValue(found, segment);
            return true;
        }
    };
    return pickRest(node.rest.items, method, rest, found, allowed);
}

fn insertValue(found: *Match, value: []const u8) void {
    @memmove(found.values[1 .. found.len + 1], found.values[0..found.len]);
    found.values[0] = value;
    found.len += 1;
}

/// The route among `routes` for `method`: its own, else `GET`'s for a
/// `HEAD`, else one for any method.
fn choose(routes: []const *const Route, method: []const u8) ?*const Route {
    var get: ?*const Route = null;
    var any: ?*const Route = null;
    for (routes) |route| {
        const m = route.pattern.method orelse {
            any = route;
            continue;
        };
        if (std.mem.eql(u8, m, method)) return route;
        if (std.mem.eql(u8, m, "GET") and std.mem.eql(u8, method, "HEAD")) get = route;
    }
    return get orelse any;
}

fn pick(routes: []const *const Route, method: []const u8, found: *Match, allowed: *Allowed) bool {
    if (choose(routes, method)) |route| {
        found.* = .{ .route = route };
        return true;
    }
    for (routes) |route| allowed.add(route.pattern.method.?);
    return false;
}

fn pickRest(routes: []const *const Route, method: []const u8, rest: []const u8, found: *Match, allowed: *Allowed) bool {
    if (choose(routes, method)) |route| {
        found.* = .{ .route = route };
        // A named rest captures it; the trailing `/` names nothing.
        if (route.pattern.segments[route.pattern.segments.len - 1].text.len != 0) {
            found.values[0] = rest;
            found.len = 1;
        }
        return true;
    }
    for (routes) |route| allowed.add(route.pattern.method.?);
    return false;
}

/// The router as the server's handler.
pub fn handler(r: *Router) Handler {
    return .init(r, serve);
}

/// Route `request`: redirect a path that is not clean or that names a
/// subtree without its `/`, answer 405 or 404, or call the handler with the
/// captures in `request.params`.
pub fn serve(r: *Router, io: Io, request: *Request, response: *Response) anyerror!void {
    return dispatch(r, io, request, response);
}

/// The router's side of `dispatch`.
pub fn find(r: *const Router, method: Method, host: []const u8, path: []const u8, allowed: *Allowed) ?Match {
    return r.match(method, host, path, allowed);
}

/// Call the handler `found` names, its captures in `request.params`.
pub fn run(_: *const Router, found: Match, io: Io, request: *Request, response: *Response) anyerror!void {
    try capture(io, request, found.route.pattern.segments, found.values[0..found.len]);
    return found.route.handler.handle(io, request, response);
}

/// What a request no pattern matches gets.
pub fn notFound(r: *const Router, io: Io, request: *Request, response: *Response) anyerror!void {
    if (r.not_found) |h| return h.handle(io, request, response);
    return plain(io, response, .not_found, "not found\n");
}

/// Answer `request` as a router does, whichever router `table` is: a
/// value with `find`, `run` and `notFound` as `Router` has them. A path
/// that is not clean is redirected to its clean form, one with a broken
/// escape is a 400, one that names a subtree without its `/` is
/// redirected to it, one that matches only under other methods is a 405
/// with `Allow`, and one nothing matches is the table's `notFound`.
pub fn dispatch(table: anytype, io: Io, request: *Request, response: *Response) anyerror!void {
    const path = request.path;
    if (request.method.eql(.CONNECT) or path.len == 0) return table.notFound(io, request, response);
    if (!validEscapes(path)) return plain(io, response, .bad_request, "bad request\n");
    if (!isClean(path)) {
        const buffer = try request.scratchBuffer(io, path.len + 1);
        return redirect(io, request, response, clean(path, buffer));
    }
    var allowed: Allowed = .{};
    if (table.find(request.method, request.host, path, &allowed)) |found| return table.run(found, io, request, response);
    if (path[path.len - 1] != '/') {
        const buffer = try request.scratchBuffer(io, path.len + 1);
        @memcpy(buffer[0..path.len], path);
        buffer[path.len] = '/';
        var ignored: Allowed = .{};
        if (table.find(request.method, request.host, buffer[0 .. path.len + 1], &ignored) != null)
            return redirect(io, request, response, buffer[0 .. path.len + 1]);
    }
    if (allowed.len != 0) {
        var list_buf: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&list_buf);
        for (allowed.sorted(), 0..) |m, i| {
            if (i != 0) w.writeAll(", ") catch break;
            w.writeAll(m) catch break;
        }
        try response.header("Allow", w.buffered());
        return plain(io, response, .method_not_allowed, "method not allowed\n");
    }
    return table.notFound(io, request, response);
}

/// Answer with `status` and a short plain-text `body`.
pub fn plain(io: Io, response: *Response, status: std.http.Status, body: []const u8) Response.Error!void {
    response.status = status;
    try response.header("Content-Type", "text/plain; charset=utf-8");
    return response.send(io, body);
}

/// A redirect to `path`, the request's query kept: 301 for a `GET` or a
/// `HEAD`, as Go answers, and 308 for any other method, whose client a
/// 301 would let change it to `GET`.
fn redirect(io: Io, request: *const Request, response: *Response, path: []const u8) Response.Error!void {
    var location_buf: [8192]u8 = undefined;
    var w: Io.Writer = .fixed(&location_buf);
    w.writeAll(path) catch return error.HeadTooLarge;
    if (request.query) |q| {
        w.writeByte('?') catch return error.HeadTooLarge;
        w.writeAll(q) catch return error.HeadTooLarge;
    }
    response.status = if (request.method.eql(.GET) or request.method.eql(.HEAD)) .moved_permanently else .permanent_redirect;
    try response.header("Location", w.buffered());
    return plain(io, response, response.status, "");
}

/// The values captured for `segments`' wildcards, their escapes undone,
/// in `request.params`.
pub fn capture(io: Io, request: *Request, segments: []const Pattern.Segment, values: []const []const u8) error{OutOfMemory}!void {
    if (values.len == 0) return;
    var need: usize = 0;
    for (values) |v| need += v.len;
    const buffer = try request.scratchBuffer(io, need);
    var at: usize = 0;
    var i: usize = 0;
    for (segments) |seg| {
        if (seg.kind != .wildcard and !(seg.kind == .multi and seg.text.len != 0)) continue;
        const value = Pattern.unescape(values[i], buffer[at..]) orelse values[i];
        if (value.ptr == buffer.ptr + at) at += value.len;
        request.params.put(seg.text, value);
        i += 1;
    }
}

fn validEscapes(path: []const u8) bool {
    var i: usize = 0;
    while (std.mem.findScalarPos(u8, path, i, '%')) |at| {
        if (at + 2 >= path.len) return false;
        if (!std.ascii.isHex(path[at + 1]) or !std.ascii.isHex(path[at + 2])) return false;
        i = at + 3;
    }
    return true;
}

/// Whether `path` has no `.` or `..` segment and no empty one but at its end.
fn isClean(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |seg| {
        const last = it.index == null;
        if (std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
        if (seg.len == 0 and !last) return false;
    }
    return true;
}

/// `path` cleaned as Go's `path.Clean`, its trailing `/` kept, into `out`.
fn clean(path: []const u8, out: []u8) []const u8 {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            // Back to the `/` before the last segment kept.
            while (n > 0 and out[n - 1] != '/') n -= 1;
            if (n > 0) n -= 1;
            continue;
        }
        out[n] = '/';
        @memcpy(out[n + 1 ..][0..seg.len], seg);
        n += 1 + seg.len;
    }
    const last = path[path.len - 1];
    const trailing = last == '/' or std.mem.endsWith(u8, path, "/.") or std.mem.endsWith(u8, path, "/..");
    if (n == 0 or trailing) {
        out[n] = '/';
        n += 1;
    }
    return out[0..n];
}

const testing = std.testing;

fn nop(_: Io, _: *Request, _: *Response) anyerror!void {}

fn matched(r: *const Router, method: Method, path: []const u8) ?[]const u8 {
    var allowed: Allowed = .{};
    const m = r.match(method, "example.com", path, &allowed) orelse return null;
    return m.pattern();
}

test "the most specific pattern wins, whatever the order they were added in" {
    var r: Router = .init(testing.allocator);
    defer r.deinit();
    const h: Handler = .of(nop);
    for ([_][]const u8{ "/", "/a/", "/a/b", "/a/{x}", "/a/{x}/c", "GET /a/b", "/static/{rest...}", "/{$}", "other.com/a/b", "/x/{y}/z/" }) |p| try r.add(p, h);
    try testing.expectEqualStrings("GET /a/b", matched(&r, .GET, "/a/b").?);
    try testing.expectEqualStrings("GET /a/b", matched(&r, .HEAD, "/a/b").?);
    try testing.expectEqualStrings("/a/b", matched(&r, .POST, "/a/b").?);
    try testing.expectEqualStrings("/a/{x}", matched(&r, .GET, "/a/q").?);
    try testing.expectEqualStrings("/a/{x}/c", matched(&r, .GET, "/a/q/c").?);
    try testing.expectEqualStrings("/a/", matched(&r, .GET, "/a/q/d").?);
    try testing.expectEqualStrings("/a/", matched(&r, .GET, "/a/").?);
    try testing.expectEqualStrings("/{$}", matched(&r, .GET, "/").?);
    try testing.expectEqualStrings("/", matched(&r, .GET, "/zzz").?);
    try testing.expectEqualStrings("/static/{rest...}", matched(&r, .GET, "/static/css/a.css").?);
    try testing.expectEqualStrings("/a/{x}", matched(&r, .GET, "/a/b%2Fc").?);
    try testing.expectEqualStrings("/x/{y}/z/", matched(&r, .GET, "/x/1/z/deep/er").?);
    var allowed: Allowed = .{};
    try testing.expectEqualStrings("other.com/a/b", r.match(.GET, "other.com:8080", "/a/b", &allowed).?.pattern());
}

test "conflicting patterns are refused, naming the one already there" {
    var r: Router = .init(testing.allocator);
    defer r.deinit();
    const h: Handler = .of(nop);
    try r.add("/a/{x}", h);
    try testing.expectError(error.Conflict, r.add("/a/{y}", h));
    try testing.expectEqualStrings("/a/{x}", r.conflict.?);
    try r.add("/{z}/b/", h);
    try testing.expectError(error.Conflict, r.add("GET /{q}/b", h));
    try testing.expectError(error.InvalidPattern, r.add("GET {h}/b", h));
    try r.add("POST /a/{x}", h);
}

test "a path under another method is gathered for Allow, and captures come back in order" {
    var r: Router = .init(testing.allocator);
    defer r.deinit();
    const h: Handler = .of(nop);
    try r.add("POST /items/{id}", h);
    try r.add("GET /items/{id}", h);
    try r.add("GET /users/{user}/repos/{repo...}", h);
    var allowed: Allowed = .{};
    try testing.expectEqual(null, r.match(.DELETE, "h", "/items/7", &allowed));
    try testing.expectEqual(@as(usize, 3), allowed.sorted().len);
    try testing.expectEqualStrings("GET", allowed.sorted()[0]);
    try testing.expectEqualStrings("HEAD", allowed.sorted()[1]);
    allowed = .{};
    const m = r.match(.GET, "h", "/users/ann/repos/zig/std", &allowed).?;
    try testing.expectEqual(@as(u8, 2), m.len);
    try testing.expectEqualStrings("ann", m.values[0]);
    try testing.expectEqualStrings("zig/std", m.values[1]);
}

test "paths are cleaned as Go cleans them" {
    var buf: [64]u8 = undefined;
    try testing.expect(isClean("/a/b/"));
    try testing.expect(!isClean("/a//b"));
    try testing.expect(!isClean("/a/./b"));
    try testing.expectEqualStrings("/a/c", clean("/a/b/../c", &buf));
    try testing.expectEqualStrings("/a/", clean("/a/b/..", &buf));
    try testing.expectEqualStrings("/", clean("/..", &buf));
    try testing.expectEqualStrings("/a/b/", clean("//a//b//", &buf));
    try testing.expect(validEscapes("/a%20b"));
    try testing.expect(!validEscapes("/a%2"));
    try testing.expect(!validEscapes("/a%zz"));
}
