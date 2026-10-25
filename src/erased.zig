//! The one conversion between a pointer a vtable carries as its context and
//! the type it was erased from. A context is erased by the type that
//! installs the vtable, and given back only to the functions it installs,
//! which restore it as that type; a `*const` erased here is read, never
//! written, through what `restore` gives back.

/// `pointer`, as a vtable's context.
pub fn erase(pointer: anytype) *anyopaque {
    return @ptrCast(@constCast(pointer)); // aegis: design: a context is restored only by the functions installed beside it, as the type erased here
}

/// The `T` that `erase` made `context` from.
pub fn restore(comptime T: type, context: ?*anyopaque) *T {
    return @ptrCast(@alignCast(context.?)); // aegis: design: every context comes from `erase` of a `T`, installed beside the function restoring it
}
