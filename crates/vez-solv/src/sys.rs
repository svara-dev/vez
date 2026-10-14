#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Hand-written mirror of libsolv's `struct s_Solvable` (solvable.h). bindgen
/// can't generate this one (see the comment in build.rs), so we blocklist its
/// broken opaque stub and define the real public-ABI layout here. Matches the
/// `#else` (non-`LIBSOLV_SOLVABLE_PREPEND_DEP`) branch, which is libsolv's
/// default.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Solvable {
    pub name: Id,
    pub arch: Id,
    pub evr: Id,
    pub vendor: Id,
    pub repo: *mut Repo,
    pub provides: Offset,
    pub obsoletes: Offset,
    pub conflicts: Offset,
    pub requires: Offset,
    pub recommends: Offset,
    pub suggests: Offset,
    pub supplements: Offset,
    pub enhances: Offset,
}

// `pool_id2solvable`/`queue_push2` are `static inline` in libsolv's headers
// (libsolv.so has no linkable symbol for them), so bindgen can't bind them
// directly. Auto-generating a wrapper for every static inline function
// libsolv declares is fragile across libsolv versions (see the comment in
// generated/static_fns.c), so we hand-wrap only the ones we call and declare
// their real symbols here.
extern "C" {
    #[link_name = "pool_id2solvable__extern"]
    pub fn pool_id2solvable(pool: *const Pool, p: Id) -> *mut Solvable;
    #[link_name = "queue_push2__extern"]
    pub fn queue_push2(q: *mut Queue, id1: Id, id2: Id);
    #[link_name = "queue_push__extern"]
    pub fn queue_push(q: *mut Queue, id: Id);
    /// Pointer to the start of a `0`-terminated run of solvable ids that
    /// provide capability/name id `d` (their own name or a `Provides:`
    /// entry). This is the lookup libsolv's own provides-based jobs
    /// (`SOLVER_SOLVABLE_PROVIDES`) use. `pool_createwhatprovides` must have
    /// run first, and the pointer is only valid until the next call that
    /// changes the pool's provides index.
    #[link_name = "pool_whatprovides_ptr__extern"]
    pub fn pool_whatprovides_ptr(pool: *mut Pool, d: Id) -> *const Id;
}
