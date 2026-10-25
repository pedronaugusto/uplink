//! What a server does for each request: a function and its context,
//! called with the request and the response that answers it.

const std = @import("std");
const erased = @import("../erased.zig");
const Io = std.Io;
const Request = @import("Request.zig");
const Response = @import("Response.zig");

const Handler = @This();

context: ?*anyopaque,
handleFn: *const fn (context: ?*anyopaque, io: Io, request: *Request, response: *Response) anyerror!void,

/// Answer `request` through `response`. An error before the response's
/// head was sent is answered with a 500; after it, the connection is
/// closed, an unfinished chunked body cut without its last chunk, so
/// the client sees a truncation, never a short success. A handler's own
/// errors pass through whatever they are: the server needs to know only
/// that one happened, and the observer is told its name.
pub fn handle(h: Handler, io: Io, request: *Request, response: *Response) anyerror!void {
    return h.handleFn(h.context, io, request, response);
}

/// A handler calling `function` with `context`, a pointer whose type
/// the function takes.
pub fn init(context: anytype, comptime function: fn (@TypeOf(context), Io, *Request, *Response) anyerror!void) Handler {
    const Context = @TypeOf(context);
    return .{
        .context = erased.erase(context),
        .handleFn = struct {
            fn call(opaque_context: ?*anyopaque, io: Io, request: *Request, response: *Response) anyerror!void {
                const typed: Context = erased.restore(@typeInfo(Context).pointer.child, opaque_context);
                return function(typed, io, request, response);
            }
        }.call,
    };
}

/// A handler calling `function`, which needs no context.
pub fn of(comptime function: fn (Io, *Request, *Response) anyerror!void) Handler {
    return .{ .context = null, .handleFn = struct {
        fn call(_: ?*anyopaque, io: Io, request: *Request, response: *Response) anyerror!void {
            return function(io, request, response);
        }
    }.call };
}
