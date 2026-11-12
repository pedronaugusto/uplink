//! `wire.uri` against RFC 3986 and RFC 3987: JSON-Schema-Test-Suite's `uri`, `uri-reference`,
//! `iri` and `iri-reference` cases (testdata/json-schema, release 23.2.0), every IPv6 form and its
//! near misses, the IRI ranges, the components pointing into the text, and properties that what
//! is accepted recomposes to the same text, on mutated references and raw bytes.
const std = @import("std");
const aegis = @import("aegis");
const shakedown = @import("shakedown");
const json_schema = @import("json_schema");
const uri = @import("uri.zig");
const testing = std.testing;
const Untrusted = aegis.input.Untrusted([]const u8);

const Case = struct { description: []const u8, data: std.json.Value, valid: bool };
const Group = struct { description: []const u8, schema: std.json.Value, tests: []const Case };

fn suite(bytes: []const u8, form: uri.Form, charset: uri.Charset) !usize {
    const parsed = try std.json.parseFromSlice([]const Group, testing.allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var n: usize = 0;
    for (parsed.value) |group| for (group.tests) |case| {
        // A format asserts nothing of a value that is no string.
        if (case.data != .string) continue;
        if (uri.check(case.data.string, form, charset) != case.valid) {
            std.debug.print("{s}: \"{s}\" should be {s}\n", .{ case.description, case.data.string, if (case.valid) "valid" else "invalid" });
            return error.TestUnexpectedResult;
        }
        n += 1;
    };
    return n;
}

test "JSON-Schema-Test-Suite's uri, uri-reference, iri and iri-reference cases" {
    try testing.expectEqualStrings("23.2.0\n", json_schema.version);
    const n = try suite(json_schema.uri, .uri, .uri) + try suite(json_schema.@"uri-reference", .reference, .uri) +
        try suite(json_schema.iri, .uri, .iri) + try suite(json_schema.@"iri-reference", .reference, .iri);
    try testing.expectEqual(43, n);
}

fn parse(s: []const u8, form: uri.Form, charset: uri.Charset) !uri.Reference {
    return uri.parse(Untrusted.init(s), form, charset, null);
}

test "the components, each pointing into the text" {
    const text = "https://user:pw@[2001:db8::7]:8080/a/b;p?q=1&r#frag";
    const r = try parse(text, .uri, .uri);
    try testing.expectEqualStrings("https", r.scheme.?);
    const a = r.authority.?;
    try testing.expectEqualStrings("user:pw", a.userinfo.?);
    try testing.expectEqualStrings("2001:db8::7", a.host.ipv6);
    try testing.expectEqualStrings("[2001:db8::7]", a.host_text);
    try testing.expectEqualStrings("8080", a.port.?);
    try testing.expectEqualStrings("/a/b;p", r.path);
    try testing.expectEqualStrings("q=1&r", r.query.?);
    try testing.expectEqualStrings("frag", r.fragment.?);
    for ([_][]const u8{ r.scheme.?, a.userinfo.?, a.host_text, a.port.?, r.path, r.query.?, r.fragment.? }) |c| {
        try testing.expect(@intFromPtr(c.ptr) >= @intFromPtr(text.ptr) and @intFromPtr(c.ptr) + c.len <= @intFromPtr(text.ptr) + text.len);
    }
    try testing.expectEqual(uri.Form.uri, r.form());
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, (try parse("http://192.0.2.1/", .uri, .uri)).authority.?.host.ipv4);
    // An all-digit name that is no IPv4 address is a reg-name.
    try testing.expectEqualStrings("256.0.0.1", (try parse("http://256.0.0.1/", .uri, .uri)).authority.?.host.name);
    try testing.expectEqualStrings("v1.x:y", (try parse("http://[v1.x:y]/", .uri, .uri)).authority.?.host.ipv_future);
    try testing.expectEqual(uri.Form.absolute, (try parse("mailto:a@b.c", .uri, .uri)).form());
    try testing.expectEqual(uri.Form.relative, (try parse("../a?b", .reference, .uri)).form());
}

test "every RFC 3986 IPv6 form, and near misses" {
    const valid = [_][]const u8{
        "1:2:3:4:5:6:7:8",     "::2:3:4:5:6:7:8", "1::3:4:5:6:7:8", "1:2::4:5:6:7:8",     "1:2:3:4:5:6::8",
        "1:2:3:4:5:6:1.2.3.4", "::1.2.3.4",       "::ffff:1.2.3.4", "1::",                "::",
        "::1",                 "1:2:3:4:5:6:7::", "ABCD:ef01::",    "1:2:3:4:5::1.2.3.4",
    };
    for (valid) |v| {
        var buffer: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "http://[{s}]/", .{v});
        errdefer std.debug.print("refused {s}\n", .{v});
        _ = try parse(text, .uri, .uri);
    }
    const invalid = [_][]const u8{
        "1:2:3:4:5:6:7:8:9",     "1:2:3:4:5:6:7", "1::2::3",   ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:",
        "12345::",               "::1.2.3",       "1.2.3.4::", "::1.2.3.04",     "fe80::1%25eth0",
        "1:2:3:4:5:6:7:1.2.3.4", "g::",           "",          "::256.1.1.1",
    };
    for (invalid) |v| {
        var buffer: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "http://[{s}]/", .{v});
        errdefer std.debug.print("accepted {s}\n", .{v});
        try testing.expectError(error.Invalid, parse(text, .uri, .uri));
    }
}

test "what RFC 3986 refuses, and where" {
    var d: uri.Diagnostic = .{};
    const refused = [_]struct { []const u8, uri.Form }{
        .{ "http://a b/", .uri },    .{ "http://a/%zz", .uri },  .{ "http://a/%2", .uri },
        .{ "http://a:8o/", .uri },   .{ "http://[::1/", .uri },  .{ "1http://a", .uri },
        .{ "//a/b", .uri },          .{ "http:a#b", .absolute }, .{ "http://a/b", .relative },
        .{ "a:b\\c", .reference },   .{ "http://a/\x01", .uri }, .{ "http://\xc3\xa9/", .uri },
        .{ "a:b", .relative },       .{ "1a:b", .reference },    .{ "http://a@b@c/", .uri },
        .{ "http://[::1]x/", .uri }, .{ "", .uri },
    };
    for (refused) |c| {
        errdefer std.debug.print("accepted {s}\n", .{c[0]});
        try testing.expectError(error.Invalid, uri.parse(Untrusted.init(c[0]), c[1], .uri, &d));
    }
    try testing.expectError(error.Invalid, uri.parse(Untrusted.init("http://a/b%g0"), .uri, .uri, &d));
    // At the '%'.
    try testing.expectEqual(10, d.offset);
    // What it takes: an empty authority, an empty port, an empty path, a bare fragment.
    for ([_][]const u8{ "file:///etc", "http://a:/", "a:", "a:#", "a:?", "urn:isbn:0-486-27557-4", "tel:+1-816-555-1212", "http:////a" }) |s| _ = try parse(s, .uri, .uri);
    for ([_][]const u8{ "", "#", "?", "../g", "g;x=1/../y", "//g", "/", ".", "./g:h" }) |s| _ = try parse(s, .reference, .uri);
}

test "IRIs: ucschar everywhere, iprivate in the query alone, no bidi formatting" {
    _ = try parse("http://例え.テスト/パス?クエリ#フラグ", .uri, .iri);
    _ = try parse("http://a/?\u{E000}", .uri, .iri);
    try testing.expectError(error.Invalid, parse("http://a/\u{E000}", .uri, .iri));
    try testing.expectError(error.Invalid, parse("http://a/#\u{E000}", .uri, .iri));
    try testing.expectError(error.Invalid, parse("http://a/\u{200E}", .uri, .iri));
    try testing.expectError(error.Invalid, parse("http://a/\u{FFFE}", .uri, .iri));
    try testing.expectError(error.Invalid, parse("http://a/\u{1FFFF}", .uri, .iri));
    try testing.expectError(error.Invalid, parse("http://a/\xc3", .uri, .iri));
    try testing.expectError(error.Invalid, parse("http://[\u{0661}::1]/", .uri, .iri));
    _ = try parse("http://a/\u{10000}\u{E1000}", .uri, .iri);
    try testing.expectError(error.Invalid, parse("http://a/\u{E0001}", .uri, .iri));
    try testing.expectError(error.Invalid, parse("http://a/é", .uri, .uri));
}

const examples = [_][]const u8{
    "https://user:pw@[2001:db8::7]:8080/a/b;p?q=1&r#frag", "http://192.0.2.1/x", "urn:isbn:0-486-27557-4",
    "../g?y#s",                                            "//g/h",              "mailto:a@b.c",
    "http://[v1.x:y]/",                                    "file:///etc/hosts",
    "http://例え.テスト/パス?q#f",
};

fn anyText(_: void, case: *shakedown.Case) !void {
    var buffer: [96]u8 = undefined;
    const s = if (shakedown.gen.boolean(case.source)) shakedown.gen.mutated(case.source, &buffer, &examples) else shakedown.gen.bytesInto(case.source, buffer[0..shakedown.gen.intRange(case.source, usize, 0, buffer.len)]);
    for ([_]uri.Charset{ .uri, .iri }) |charset| for (std.enums.values(uri.Form)) |form| {
        const r = parse(s, form, charset) catch continue;
        // What is accepted recomposes to itself, and is the form it was read as.
        var out: [128]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try r.format(&w);
        try testing.expectEqualStrings(s, w.buffered());
        try testing.expect(uri.check(s, .reference, charset));
        if (form == .uri or form == .absolute) try testing.expect(r.scheme != null);
        // An IRI's charset holds a URI's.
        if (charset == .uri) try testing.expect(uri.check(s, form, .iri));
    };
}

test "fuzz: on mutated references and raw bytes, what is accepted recomposes to itself" {
    try shakedown.check(testing.allocator, {}, anyText, .{ .cases = 5000, .seed = 0x3986 });
}

test "Appendix B's split takes any text apart, unchecked" {
    const s = uri.split("http://a b@h/p q?x?y#f#g");
    try testing.expectEqualStrings("http", s.scheme.?);
    try testing.expectEqualStrings("a b@h", s.authority.?);
    try testing.expectEqualStrings("/p q", s.path);
    try testing.expectEqualStrings("x?y", s.query.?);
    try testing.expectEqualStrings("f#g", s.fragment.?);
    const relative = uri.split("a/b:c");
    try testing.expectEqual(@as(?[]const u8, null), relative.scheme);
    try testing.expectEqualStrings("a/b:c", relative.path);
    try testing.expectEqual(@as(?[]const u8, null), uri.split(":x").scheme);
    try testing.expectEqualStrings("1a", uri.split("1a://h").scheme.?);
    const empty = uri.split("");
    try testing.expect(empty.scheme == null and empty.authority == null and empty.query == null and empty.fragment == null);
    try testing.expectEqualStrings("", empty.path);
}

fn anySplit(_: void, case: *shakedown.Case) !void {
    var buffer: [96]u8 = undefined;
    const s = if (shakedown.gen.boolean(case.source)) shakedown.gen.mutated(case.source, &buffer, &examples) else shakedown.gen.bytesInto(case.source, buffer[0..shakedown.gen.intRange(case.source, usize, 0, buffer.len)]);
    const parts = uri.split(s);
    // The parts, put back with their delimiters, are the text.
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    if (parts.scheme) |scheme| try w.print("{s}:", .{scheme});
    if (parts.authority) |authority| try w.print("//{s}", .{authority});
    try w.writeAll(parts.path);
    if (parts.query) |query| try w.print("?{s}", .{query});
    if (parts.fragment) |fragment| try w.print("#{s}", .{fragment});
    try testing.expectEqualStrings(s, w.buffered());
    // A reference `parse` accepts splits into the same parts.
    const r = parse(s, .reference, .iri) catch return;
    try testing.expectEqualDeep(r.scheme, parts.scheme);
    try testing.expectEqualDeep(r.path, parts.path);
    try testing.expectEqualDeep(r.query, parts.query);
    try testing.expectEqualDeep(r.fragment, parts.fragment);
    try testing.expectEqual(r.authority != null, parts.authority != null);
}

test "fuzz: split puts back to the text, and agrees with parse where parse accepts" {
    try shakedown.check(testing.allocator, {}, anySplit, .{ .cases = 5000, .seed = 0xB });
}

test "RFC 3986 §5.4: all 42 resolution examples, 23 normal and 19 abnormal" {
    const base = try parse("http://a/b/c/d;p?q", .uri, .uri);
    const cases = [_]struct { []const u8, []const u8 }{
        // §5.4.1, normal.
        .{ "g:h", "g:h" },                      .{ "g", "http://a/b/c/g" },               .{ "./g", "http://a/b/c/g" },
        .{ "g/", "http://a/b/c/g/" },           .{ "/g", "http://a/g" },                  .{ "//g", "http://g" },
        .{ "?y", "http://a/b/c/d;p?y" },        .{ "g?y", "http://a/b/c/g?y" },           .{ "#s", "http://a/b/c/d;p?q#s" },
        .{ "g#s", "http://a/b/c/g#s" },         .{ "g?y#s", "http://a/b/c/g?y#s" },       .{ ";x", "http://a/b/c/;x" },
        .{ "g;x", "http://a/b/c/g;x" },         .{ "g;x?y#s", "http://a/b/c/g;x?y#s" },   .{ "", "http://a/b/c/d;p?q" },
        .{ ".", "http://a/b/c/" },              .{ "./", "http://a/b/c/" },               .{ "..", "http://a/b/" },
        .{ "../", "http://a/b/" },              .{ "../g", "http://a/b/g" },              .{ "../..", "http://a/" },
        .{ "../../", "http://a/" },             .{ "../../g", "http://a/g" },
        // §5.4.2, abnormal.
                    .{ "../../../g", "http://a/g" },
        .{ "../../../../g", "http://a/g" },     .{ "/./g", "http://a/g" },                .{ "/../g", "http://a/g" },
        .{ "g.", "http://a/b/c/g." },           .{ ".g", "http://a/b/c/.g" },             .{ "g..", "http://a/b/c/g.." },
        .{ "..g", "http://a/b/c/..g" },         .{ "./../g", "http://a/b/g" },            .{ "./g/.", "http://a/b/c/g/" },
        .{ "g/./h", "http://a/b/c/g/h" },       .{ "g/../h", "http://a/b/c/h" },          .{ "g;x=1/./y", "http://a/b/c/g;x=1/y" },
        .{ "g;x=1/../y", "http://a/b/c/y" },    .{ "g?y/./x", "http://a/b/c/g?y/./x" },   .{ "g?y/../x", "http://a/b/c/g?y/../x" },
        .{ "g#s/./x", "http://a/b/c/g#s/./x" }, .{ "g#s/../x", "http://a/b/c/g#s/../x" },
        // A strict parser takes the scheme as written (§5.4.2's last example).
        .{ "http:g", "http:g" },
    };
    try testing.expectEqual(42, cases.len);
    for (cases) |e| {
        var out: [64]u8 = undefined;
        const ref = try parse(e[0], .reference, .uri);
        errdefer std.debug.print("{s}\n", .{e[0]});
        try testing.expectEqualStrings(e[1], try uri.resolve(base, ref, &out));
    }
    var small: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, uri.resolve(base, try parse("g", .reference, .uri), &small));
    var out: [64]u8 = undefined;
    try testing.expectError(error.NotAbsolute, uri.resolve(try parse("/a", .reference, .uri), try parse("g", .reference, .uri), &out));
    // A base with an authority and no path merges onto "/"; a base's fragment is dropped.
    try testing.expectEqualStrings("http://a/g", try uri.resolve(try parse("http://a", .uri, .uri), try parse("g", .reference, .uri), &out));
    try testing.expectEqualStrings("http://a/b/g", try uri.resolve(try parse("http://a/b/c#f", .uri, .uri), try parse("g", .reference, .uri), &out));
}

fn anyResolution(_: void, case: *shakedown.Case) !void {
    var base_buffer: [96]u8 = undefined;
    var ref_buffer: [96]u8 = undefined;
    const base_text = shakedown.gen.mutated(case.source, &base_buffer, &.{ "http://a/b/c/d;p?q", "https://x.y/z/", "urn:a:b", "file:///", "http://[::1]:80/a/../b" });
    const ref_text = shakedown.gen.mutated(case.source, &ref_buffer, &.{ "../g?y#s", "./../g", "//h/i", "g;x=1/../y", ".", "..", "/./g", "?q", "#f", "a:b" });
    const base = parse(base_text, .uri, .uri) catch return;
    const ref = parse(ref_text, .reference, .uri) catch return;
    var out: [256]u8 = undefined;
    const target = try uri.resolve(base, ref, &out);
    // What resolution makes is a URI, with no "." or ".." segment left in its path.
    const t = try parse(target, .uri, .uri);
    var segments = std.mem.splitScalar(u8, t.path, '/');
    while (segments.next()) |s| {
        try testing.expect(!std.mem.eql(u8, s, ".") and !std.mem.eql(u8, s, ".."));
    }
}

test "property: a resolution is a URI with no dot segments left" {
    try shakedown.check(testing.allocator, {}, anyResolution, .{ .cases = 3000, .seed = 0x3987 });
}
