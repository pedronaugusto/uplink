//! What a server does for each request: a function called with the request
//! and the response that answers it. A handler is a field of the type that
//! answers, which its function finds by `@fieldParentPtr`; a server holds a
//! pointer to it.

const std = @import("std");
const Io = std.Io;
const Request = @import("Request.zig");
const Response = @import("Response.zig");

const Handler = @This();

handleFn: *const fn (h: *const Handler, io: Io, request: *Request, response: *Response) anyerror!void,

/// Answer `request` through `response`. An error before the response's
/// head was sent is answered with a 500; after it, the connection is
/// closed, an unfinished chunked body cut without its last chunk, so
/// the client sees a truncation, never a short success. A handler's own
/// errors pass through whatever they are: the server needs to know only
/// that one happened, and the observer is told its name.
pub fn handle(h: *const Handler, io: Io, request: *Request, response: *Response) anyerror!void {
    return h.handleFn(h, io, request, response);
}

/// A handler calling `function`, which needs nothing else: one for each
/// function, made at compile time.
pub fn of(comptime function: fn (Io, *Request, *Response) anyerror!void) *const Handler {
    return &struct {
        const handler: Handler = .{ .handleFn = call };
        fn call(_: *const Handler, io: Io, request: *Request, response: *Response) anyerror!void {
            return function(io, request, response);
        }
    }.handler;
}
