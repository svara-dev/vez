#include "wrapper.h"

// Maintained by hand, not bindgen output. libsolv's headers declare dozens of
// `static inline` helpers (hash.h, queue.h, pool.h, ...), and bindgen's
// wrap_static_fns emits a non-inline `<name>__extern` wrapper for every one
// reachable from wrapper.h, whether we call it or not. That works on the
// libsolv version it was generated against, but static inline functions
// aren't part of libsolv's stable ABI: EL10 (libsolv 0.7.33) doesn't declare
// `allochashtable` and friends that newer Fedora libsolv does, so a vendored
// full dump fails to compile there with "implicit declaration of function
// 'allochashtable'". Only wrap the static inline functions rum-solv calls
// (see src/lib.rs). They've been in libsolv from the start, so this works on
// every libsolv version we target.

Solvable * pool_id2solvable__extern(const Pool *pool, Id p) { return pool_id2solvable(pool, p); }
void queue_push2__extern(Queue *q, Id id1, Id id2) { queue_push2(q, id1, id2); }
void queue_push__extern(Queue *q, Id id) { queue_push(q, id); }
Id * pool_whatprovides_ptr__extern(Pool *pool, Id d) { return pool_whatprovides_ptr(pool, d); }
