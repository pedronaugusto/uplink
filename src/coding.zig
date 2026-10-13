//! Content codings, both ways, through warp: a body's codings undone as it
//! is read, and a body put under one as it is written. The client and the
//! server share it; neither holds a codec of its own.

/// A body's codings undone, with every checksum verified.
pub const Decoder = @import("coding/Decoder.zig");
/// The memory a zstd body is decoded in, and the cap on its window.
pub const ZstdBuffer = @import("coding/ZstdBuffer.zig");

test {
    _ = Decoder;
    _ = ZstdBuffer;
}
