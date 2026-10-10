//! A hook a client calls before every attempt of every request, after
//! redirects and retries have decided where it goes and before a byte of it
//! is written: the one place a request is changed on its way out. A
//! signature that covers the URL or a date (AWS SigV4, HTTP Message
//! Signatures) is made here, so it is made again for each redirect and
//! retry rather than once and then stale.

const std = @import("std");
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const Method = wire.Method;

const Prepare = @This();

context: ?*anyopaque,
prepareFn: *const fn (io: Io, context: ?*anyopaque, attempt: *Attempt) Error!void,

/// Why an attempt could not be prepared. The request fails with
/// `PrepareFailed`.
pub const Error = error{ PrepareFailed, Canceled };

/// Run the hook.
pub fn run(p: Prepare, io: Io, attempt: *Attempt) Error!void {
    return p.prepareFn(io, p.context, attempt);
}

/// One attempt, about to be written.
pub const Attempt = struct {
    method: Method,
    /// Where it goes, after any redirect.
    url: []const u8,
    /// The request's own fields, as they will be written.
    headers: []const std.http.Header,
    /// The body's bytes, when the request has them whole; null for none or
    /// a body from a reader or the caller.
    body: ?[]const u8,
    /// 1 for the first attempt; each redirect, retry and answered
    /// challenge adds one.
    number: u8,
    /// Private: the fields added.
    added: [max_added]std.http.Header = undefined,
    added_len: u8 = 0,

    /// The most fields a hook may add.
    pub const max_added = 16;

    /// Errors from `add`.
    pub const AddError = error{
        /// Past `max_added`.
        TooManyHeaders,
        /// Not a field that can be sent, or one the client writes itself.
        InvalidHeader,
    };

    /// Add a field after the request's own. Its name and value must stay
    /// valid until the attempt is written: until the hook is next called
    /// for this request, or the request returns.
    pub fn add(a: *Attempt, header: std.http.Header) AddError!void {
        h1.checkHeader(header) catch return error.InvalidHeader;
        for ([_][]const u8{ "host", "content-length", "transfer-encoding" }) |own| {
            if (std.ascii.eqlIgnoreCase(header.name, own)) return error.InvalidHeader;
        }
        if (a.added_len == max_added) return error.TooManyHeaders;
        a.added[a.added_len] = header;
        a.added_len += 1;
    }

    /// The fields the hook added, in order.
    pub fn addedHeaders(a: *const Attempt) []const std.http.Header {
        return a.added[0..a.added_len];
    }
};

test "a hook adds checked fields, up to its limit" {
    var a: Attempt = .{ .method = .GET, .url = "https://h/", .headers = &.{}, .body = null, .number = 1 };
    try a.add(.{ .name = "X-Signature", .value = "abc" });
    try std.testing.expectError(error.InvalidHeader, a.add(.{ .name = "Host", .value = "evil" }));
    try std.testing.expectError(error.InvalidHeader, a.add(.{ .name = "X", .value = "a\r\nb" }));
    for (1..Attempt.max_added) |_| try a.add(.{ .name = "X-Pad", .value = "1" });
    try std.testing.expectError(error.TooManyHeaders, a.add(.{ .name = "X-More", .value = "1" }));
    try std.testing.expectEqualStrings("X-Signature", a.addedHeaders()[0].name);
}
