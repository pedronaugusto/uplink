//! Content codings, both ways, through warp: a body's codings undone as it
//! is read, and a body put under one as it is written. The client and the
//! server share it; neither holds a codec of its own.

/// A body's codings undone, with every checksum verified.
pub const Decoder = @import("coding/Decoder.zig");
const windows = @import("coding/windows.zig");
/// The memory a zstd body is decoded in, and the cap on its window.
pub const ZstdBuffer = windows.ZstdBuffer;
/// The memory a Brotli body is decoded in, and the cap on its window.
pub const BrotliBuffer = windows.BrotliBuffer;
/// Both, as a client or a server holds them.
pub const Windows = windows.Windows;
/// A body put under a coding as it is written.
pub const Encoder = @import("coding/Encoder.zig");

test {
    _ = Decoder;
    _ = windows;
    _ = Encoder;
}
