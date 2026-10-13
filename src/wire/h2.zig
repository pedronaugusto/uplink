//! HTTP/2 (RFC 9113), sans I/O: its frames, and a connection's protocol
//! state over them.

const frame = @import("h2/frame.zig");

/// Frame heads, payloads, settings and error codes.
pub const Frame = frame;
/// The client's connection preface.
pub const preface = frame.preface;
pub const head_len = frame.head_len;
pub const Head = frame.Head;
pub const FrameType = frame.FrameType;
pub const Flags = frame.Flags;
pub const ErrorCode = frame.ErrorCode;
pub const Settings = frame.Settings;
pub const writeFrame = frame.writeFrame;
/// One connection's protocol state.
pub const Connection = @import("h2/Connection.zig");
/// Messages as fields: blocks checked, built from lines, kept.
pub const message = @import("h2/message.zig");

test {
    _ = frame;
    _ = Connection;
    _ = message;
}
