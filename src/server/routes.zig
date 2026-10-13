//! A router whose patterns are known at compile time: the same grammar
//! and the same answers as `Router` (Go 1.22's semantics), with two
//! differences that the compiler makes possible. Two patterns that
//! conflict are a compile error naming both, and each handler takes its
//! captures as a struct with a `[]const u8` field per wildcard, named as
//! the pattern names it, so a capture that does not exist does not
//! compile.
//!
//! ```
//! const api = uplink.server.Routes(.{
//!     .{ "GET /users/{id}", getUser },
//!     .{ "POST /users", createUser },
//! });
//! fn getUser(io: Io, request: *Request, response: *Response, captures: uplink.server.Captures("GET /users/{id}")) !void {
//!     ... captures.id ...
//! }
//! var server: uplink.Server = .init(gpa, .{}, api.handler());
//! ```
//!
//! The patterns are ordered at compile time, the more specific before the
//! more general, and a request is matched against them in that order, each
//! match unrolled into the comparisons its literal segments need.

const std = @import("std");
const Io = std.Io;
const wire = @import("uplink.wire");
const Method = wire.Method;
const Pattern = @import("Pattern.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Handler = @import("Handler.zig");
const Router = @import("Router.zig");

/// `pattern` parsed at compile time, its storage its own.
fn parsed(comptime pattern: []const u8) Pattern {
    comptime {
        var segments: [Pattern.countSegments(pattern)]Pattern.Segment = undefined;
        var scratch: [pattern.len]u8 = undefined;
        const p = Pattern.parse(pattern, &segments, &scratch) catch @compileError("not a route pattern: \"" ++ pattern ++ "\"");
        const kept_segments = segments[0..p.segments.len].*;
        var copies: [p.segments.len]Pattern.Segment = kept_segments;
        // Literals unescaped into the scratch keep their text in a copy of
        // their own.
        for (&copies) |*seg| {
            const text = seg.text[0..seg.text.len].*;
            seg.text = &text;
        }
        const frozen = copies;
        return .{ .text = pattern, .method = p.method, .host = p.host, .segments = &frozen };
    }
}

/// The names of `pattern`'s wildcards, in order.
fn wildcardNames(comptime p: Pattern) []const []const u8 {
    comptime {
        var names: [p.segments.len][]const u8 = undefined;
        var n = 0;
        for (p.segments) |seg| if (seg.kind == .wildcard or (seg.kind == .multi and seg.text.len != 0)) {
            names[n] = seg.text;
            n += 1;
        };
        const kept = names[0..n].*;
        return &kept;
    }
}

/// The captures of `pattern`: a `[]const u8` field per wildcard, with its
/// escapes undone.
pub fn Captures(comptime pattern: []const u8) type {
    const names = wildcardNames(parsed(pattern));
    const types: [names.len]type = @splat([]const u8);
    return @Struct(.auto, null, names, &types, &@splat(.{}));
}

/// A router over `table`, a tuple of `.{ pattern, handler }`, each
/// handler a `fn (Io, *Request, *Response, Captures(pattern)) anyerror!void`.
pub fn Routes(comptime table: anytype) type {
    const count = table.len;
    const patterns: [count]Pattern = comptime blk: {
        var ps: [count]Pattern = undefined;
        for (0..count) |i| ps[i] = parsed(table[i][0]);
        for (0..count) |i| for (i + 1..count) |j| {
            if (ps[i].conflicts(&ps[j])) @compileError("route \"" ++ ps[j].text ++ "\" conflicts with \"" ++ ps[i].text ++ "\"");
        };
        for (0..count) |i| {
            const Want = fn (Io, *Request, *Response, Captures(table[i][0])) anyerror!void;
            if (@TypeOf(table[i][1]) != Want) @compileError("the handler of \"" ++ ps[i].text ++ "\" is not a " ++ @typeName(Want));
        }
        break :blk ps;
    };
    // The more specific first: each pattern goes after every one more
    // specific than it among those it overlaps, and one with a host before
    // any without.
    const order: [count]usize = comptime blk: {
        var placed: [count]bool = @splat(false);
        var out: [count]usize = undefined;
        for (0..count) |k| {
            const next = pick: for (0..count) |i| {
                if (placed[i]) continue;
                for (0..count) |j| {
                    if (placed[j] or j == i) continue;
                    if (before(&patterns[j], &patterns[i])) continue :pick;
                }
                break :pick i;
            } else unreachable;
            placed[next] = true;
            out[k] = next;
        }
        break :blk out;
    };
    return struct {
        const Self = @This();

        /// The routes as the server's handler.
        pub fn handler() Handler {
            return .of(serve);
        }

        /// Route `request` as `Router.dispatch` does.
        pub fn serve(io: Io, request: *Request, response: *Response) anyerror!void {
            return Router.dispatch(Self{}, io, request, response);
        }

        pub const Hit = struct {
            index: usize,
            values: [Pattern.max_wildcards][]const u8 = undefined,
            len: u8 = 0,
        };

        pub fn find(_: Self, method: Method, host: []const u8, path: []const u8, allowed: *Router.Allowed) ?Hit {
            const name = Router.hostName(host);
            inline for (order) |i| {
                const p = comptime &patterns[i];
                const host_ok = if (comptime p.host) |h| std.ascii.eqlIgnoreCase(h, name) else true;
                if (host_ok) {
                    var hit: Hit = .{ .index = i };
                    if (p.matchPath(path, &hit.values)) |n| {
                        if (p.takesMethod(method.name)) {
                            hit.len = n;
                            return hit;
                        }
                        allowed.add(p.method.?);
                    }
                }
            }
            return null;
        }

        pub fn run(_: Self, hit: Hit, io: Io, request: *Request, response: *Response) anyerror!void {
            inline for (0..count) |i| if (hit.index == i) {
                const p = comptime &patterns[i];
                try Router.capture(io, request, p.segments, hit.values[0..hit.len]);
                var captures: Captures(table[i][0]) = undefined;
                inline for (comptime wildcardNames(p.*)) |field| @field(captures, field) = request.param(field).?;
                return table[i][1](io, request, response, captures);
            };
            unreachable; // unreachable: `find` names a route of the table
        }

        pub fn notFound(_: Self, io: Io, _: *Request, response: *Response) anyerror!void {
            return Router.plain(io, response, .not_found, "not found\n");
        }
    };
}

/// Whether `a` must be tried before `b`: it has a host and `b` has none,
/// or both have the same host and `a` is more specific.
fn before(comptime a: *const Pattern, comptime b: *const Pattern) bool {
    if (a.host != null and b.host == null) return true;
    if ((a.host == null) != (b.host == null)) return false;
    if (a.host) |h| if (!std.ascii.eqlIgnoreCase(h, b.host.?)) return false;
    return a.compare(b) == .more_specific;
}

const testing = std.testing;

fn user(io: Io, _: *Request, response: *Response, captures: Captures("GET /users/{id}")) anyerror!void {
    var buf: [64]u8 = undefined;
    try response.send(io, try std.mem.print(&buf, "user {s}", .{captures.id}));
}

fn anyUser(io: Io, _: *Request, response: *Response, captures: Captures("/users/{rest...}")) anyerror!void {
    var buf: [64]u8 = undefined;
    try response.send(io, try std.mem.print(&buf, "rest {s}", .{captures.rest}));
}

test "comptime routes order their patterns by specificity and type their captures" {
    const R = Routes(.{
        .{ "/users/{rest...}", anyUser },
        .{ "GET /users/{id}", user },
    });
    var allowed: Router.Allowed = .{};
    const hit = R.find(.{}, .GET, "h", "/users/7", &allowed).?;
    try testing.expectEqual(@as(usize, 1), hit.index);
    try testing.expectEqualStrings("7", hit.values[0]);
    const deep = R.find(.{}, .GET, "h", "/users/7/repos", &allowed).?;
    try testing.expectEqual(@as(usize, 0), deep.index);
    try testing.expectEqual(null, R.find(.{}, .GET, "h", "/other", &allowed));
    const C = Captures("GET /a/{x}/b/{y...}");
    try testing.expect(@hasField(C, "x") and @hasField(C, "y"));
}
