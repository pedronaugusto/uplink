//! The DNS servers Windows gives its adapters, as `GetAdaptersAddresses`
//! reports them: the servers of every adapter that is up, in the system's
//! order, at most three.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;

const Ulong = u32;

/// The start of `IP_ADAPTER_ADDRESSES_LH`, as far as this reads it; the
/// system allocates and lays out the whole.
const Adapter = extern struct {
    length: Ulong,
    if_index: Ulong,
    next: ?*Adapter,
    adapter_name: ?[*:0]u8,
    first_unicast: ?*anyopaque,
    first_anycast: ?*anyopaque,
    first_multicast: ?*anyopaque,
    first_dns_server: ?*DnsServer,
    dns_suffix: ?[*:0]u16,
    description: ?[*:0]u16,
    friendly_name: ?[*:0]u16,
    physical_address: [8]u8,
    physical_address_length: Ulong,
    flags: Ulong,
    mtu: Ulong,
    if_type: Ulong,
    oper_status: Ulong,
};

/// `IP_ADAPTER_DNS_SERVER_ADDRESS_XP`.
const DnsServer = extern struct {
    length: Ulong,
    reserved: Ulong,
    next: ?*DnsServer,
    address: SocketAddress,
};

/// `SOCKET_ADDRESS`.
const SocketAddress = extern struct {
    sockaddr: ?*const anyopaque,
    sockaddr_length: i32,
};

const if_oper_status_up = 1;
const gaa_flag_skip_unicast = 0x1;
const gaa_flag_skip_anycast = 0x2;
const gaa_flag_skip_multicast = 0x4;
const gaa_flag_skip_friendly_name = 0x20;

// aegis: boundary: iphlpapi's GetAdaptersAddresses, declared as Windows documents it; `load` is its one caller
extern "iphlpapi" fn GetAdaptersAddresses(family: Ulong, flags: Ulong, reserved: ?*anyopaque, addresses: ?*Adapter, size: *Ulong) callconv(.winapi) Ulong;

/// The servers of the adapters that are up, into `servers`, using
/// `buffer` for the system's records; how many, or null when the system
/// could not say (a buffer too small for its records among the reasons).
pub fn load(servers: []IpAddress, buffer: []align(8) u8) ?usize {
    if (builtin.os.tag != .windows) unreachable; // unreachable: `Dns.System.load` calls this on Windows alone
    var size: Ulong = @intCast(@min(buffer.len, std.math.maxInt(Ulong))); // safe: clamped to a Ulong
    const first: *Adapter = @ptrCast(buffer.ptr); // aegis: boundary: the system writes its adapter records into this 8-aligned buffer
    const status = GetAdaptersAddresses(0, gaa_flag_skip_unicast | gaa_flag_skip_anycast | gaa_flag_skip_multicast | gaa_flag_skip_friendly_name, null, first, &size);
    if (status != 0) return null;
    var count: usize = 0;
    var adapter: ?*Adapter = first;
    while (adapter) |a| : (adapter = a.next) {
        if (a.oper_status != if_oper_status_up) continue;
        var server = a.first_dns_server;
        while (server) |s| : (server = s.next) {
            if (count == servers.len) return count;
            const address = fromSockaddr(s.address) orelse continue;
            const known = for (servers[0..count]) |k| {
                if (k.eql(&address)) break true;
            } else false;
            if (known) continue;
            servers[count] = address;
            count += 1;
        }
    }
    return count;
}

fn fromSockaddr(a: SocketAddress) ?IpAddress {
    const raw: [*]const u8 = @ptrCast(a.sockaddr orelse return null); // aegis: boundary: a sockaddr the system wrote, read as its bytes
    const len: usize = @intCast(@max(a.sockaddr_length, 0)); // safe: clamped at zero
    if (len < 2) return null;
    const family = std.mem.readInt(u16, raw[0..2], .little);
    switch (family) {
        2 => {
            if (len < 8) return null;
            return .{ .ip4 = .{ .bytes = raw[4..8].*, .port = 53 } };
        },
        23 => {
            if (len < 28) return null;
            const scope = std.mem.readInt(u32, raw[24..28], .little);
            const bytes = raw[8..24].*;
            // A site-local resolver Windows lists while none is set
            // (fec0:0:0:ffff::1, ::2 and ::3) answers nothing.
            if (bytes[0] == 0xfe and bytes[1] == 0xc0) return null;
            return .{ .ip6 = .{ .bytes = bytes, .port = 53, .interface = .{ .index = scope } } };
        },
        else => return null,
    }
}
