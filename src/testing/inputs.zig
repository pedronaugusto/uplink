//! Byte inputs for the codec properties: arbitrary bytes, or a known-good
//! example with a few of its bytes overwritten and its tail cut.
const shakedown = @import("shakedown");
const gen = shakedown.gen;

/// Fills a prefix of `buffer` and returns it. Half the cases start from one of
/// `seeds` so that a parser is driven past its first checks; the rest are
/// arbitrary bytes, `average` long on average.
pub fn draw(case: *shakedown.Case, buffer: []u8, seeds: []const []const u8, average: u32) []u8 {
    const s = case.source;
    if (seeds.len != 0 and gen.boolean(s)) {
        const seed = gen.oneOf(s, []const u8, seeds);
        const n = @min(seed.len, buffer.len);
        @memcpy(buffer[0..n], seed[0..n]);
        if (n == 0) return buffer[0..0];
        var edits = gen.intRange(s, u8, 0, 6);
        while (edits > 0) : (edits -= 1) buffer[gen.intRange(s, usize, 0, n - 1)] = gen.int(s, u8);
        return buffer[0..if (gen.boolean(s)) gen.intRange(s, usize, 0, n) else n];
    }
    var len: usize = 0;
    while (len < buffer.len and s.more(average)) : (len += 1) buffer[len] = gen.int(s, u8);
    return buffer[0..len];
}
