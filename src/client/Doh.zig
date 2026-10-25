//! DNS over HTTPS (RFC 8484): a `Dns.Transport` that posts each query to a
//! server's URL as `application/dns-message` through a client of its own,
//! and takes the answer from the response's body.
//!
//! The client it posts through must not resolve names with a `Dns` over
//! this transport: it reaches the DoH server by the system's lookup, by
//! an address in the URL, or by a `Resolver.Static` entry for its name.

const std = @import("std");
const erased = @import("../erased.zig");
const Io = std.Io;
const dns = @import("uplink.wire").dns;
const Dns = @import("../net/Dns.zig");
const Client = @import("Client.zig");

const Doh = @This();

client: *Client,
/// The server's URL, `https://dns.example/dns-query` say.
url: []const u8,

pub fn transport(d: *const Doh) Dns.Transport {
    return .{ .context = erased.erase(d), .exchangeFn = exchange };
}

const media_type = "application/dns-message";

fn exchange(io: Io, context: ?*anyopaque, query: []const u8, answer: []u8) Dns.ExchangeError![]u8 {
    const d: *const Doh = erased.restore(Doh, context);
    if (query.len < dns.header_len or query.len > dns.max_message) return error.NoAnswer;
    // The id goes as 0, so equal queries are equal requests a cache can
    // answer (§4.1); the answer gets the query's own back.
    var sent: [dns.max_name + 64]u8 = undefined;
    if (query.len > sent.len) return error.NoAnswer;
    @memcpy(sent[0..query.len], query);
    sent[0] = 0;
    sent[1] = 0;
    var response = d.client.send(io, .{
        .url = d.url,
        .method = .POST,
        .headers = &.{ .{ .name = "Content-Type", .value = media_type }, .{ .name = "Accept", .value = media_type } },
        .body = .{ .bytes = sent[0..query.len] },
    }) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        else => error.NoAnswer,
    };
    defer response.deinit(io);
    if (response.status != .ok) return error.NoAnswer;
    const content_type = response.headers.get("content-type") orelse return error.NoAnswer;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, content_type, " \t"), media_type)) return error.NoAnswer;
    const r = response.reader(io);
    const n = r.readSliceShort(answer) catch |err| return switch (err) {
        error.ReadFailed => if (response.failure() == error.Canceled) error.Canceled else error.NoAnswer,
    };
    // An answer longer than any DNS message is no DNS answer.
    if (n == answer.len and (r.discardRemaining() catch 1) != 0) return error.NoAnswer;
    const got = answer[0..n];
    if (!Dns.sameQuestion(sent[0..query.len], got)) return error.NoAnswer;
    got[0] = query[0];
    got[1] = query[1];
    return got;
}
