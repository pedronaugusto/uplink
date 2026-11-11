//! Test-only: certificates cloak issues in process, each self-signed: a
//! server's for `server.test`, `localhost` and 127.0.0.1, and a client's,
//! with each side's trust in the other's. No `openssl`, no file, nothing
//! outside the test. Valid from 2025 to 2036, around both the system's
//! clock and a simulation's (2026).

const std = @import("std");
const cloak = @import("cloak");
const testing = std.testing;

const Pki = @This();

server_key: cloak.PrivateKey,
server_leaf: []u8,
identity: cloak.Identity,
/// A server's credentials: its certificate and key.
credentials: [1]cloak.tls.Credential,
/// A client's trust in the server's certificate.
trust: cloak.Trust.Snapshot,
client_key: cloak.PrivateKey,
client_leaf: []u8,
/// A client's certificate and key, for a server that asks for one.
client_auth: cloak.ClientAuth,
/// A server's trust in the client's certificate.
client_trust: cloak.Trust.Snapshot,

pub fn init(p: *Pki) !void {
    const gpa = testing.allocator;
    p.server_key = try cloak.PrivateKey.generate(gpa, testing.io, .p256);
    errdefer p.server_key.deinit();
    p.server_leaf = try issue(p.server_key, "server.test", &.{ .{ .dns = "server.test" }, .{ .dns = "localhost" }, .{ .ip = &.{ 127, 0, 0, 1 } } }, .server_auth);
    errdefer gpa.free(p.server_leaf);
    p.identity = try cloak.Identity.init(gpa, &.{p.server_leaf}, p.server_key, .{});
    errdefer p.identity.deinit();
    p.trust = try trusting(p.server_leaf);
    errdefer p.trust.deinit();
    p.credentials = .{.{ .identity = p.identity }};
    p.client_key = try cloak.PrivateKey.generate(gpa, testing.io, .p256);
    errdefer p.client_key.deinit();
    p.client_leaf = try issue(p.client_key, "client", &.{.{ .dns = "client.test" }}, .client_auth);
    errdefer gpa.free(p.client_leaf);
    p.client_auth = try cloak.ClientAuth.init(gpa, &.{p.client_leaf}, p.client_key, .{});
    errdefer p.client_auth.deinit();
    p.client_trust = try trusting(p.client_leaf);
}

pub fn deinit(p: *Pki) void {
    const gpa = testing.allocator;
    p.client_trust.deinit();
    p.client_auth.deinit();
    gpa.free(p.client_leaf);
    p.client_key.deinit();
    p.trust.deinit();
    p.identity.deinit();
    gpa.free(p.server_leaf);
    p.server_key.deinit();
}

fn issue(key: cloak.PrivateKey, common_name: []const u8, names: []const cloak.certificates.template.AltName, purpose: cloak.certificates.template.Purpose) ![]u8 {
    var spki: [cloak.PrivateKey.max_public_key_info]u8 = undefined;
    return cloak.certificates.issue(testing.allocator, testing.io, &.{
        .subject = .{ .attributes = &.{.{ .common_name = common_name }} },
        .not_before = .fromNanoseconds(@as(i96, 1_735_689_600) * std.time.ns_per_s),
        .not_after = .fromNanoseconds(@as(i96, 2_082_758_400) * std.time.ns_per_s),
        .names = names,
        .key_usage = .{ .digital_signature = true },
        .purposes = &.{purpose},
    }, key.publicKeyInfo(&spki), .{ .key = key });
}

fn trusting(leaf: []const u8) !cloak.Trust.Snapshot {
    var builder: cloak.Trust = .init(testing.allocator);
    defer builder.deinit();
    try builder.addDer(leaf, .{});
    return builder.freeze();
}
