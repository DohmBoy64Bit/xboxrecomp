/**
 * Target-neutral Xbox memory-layout compatibility header.
 *
 * The canonical runtime parses section coordinates, entry metadata, and the
 * kernel-thunk table from the exact XBE. It then selects non-overlapping
 * runtime storage for kernel exports, the simulated stack, and the heap.
 * Game projects must not copy reference-title section or runtime addresses
 * into this header.
 *
 * New projects should include xbox_memory_layout.h directly. These aliases
 * preserve the historical template API while routing every operation through
 * the canonical dynamic implementation.
 */

#ifndef XBOX_MEMORY_H
#define XBOX_MEMORY_H

#include "xbox_memory_layout.h"

#define xbox_memory_init         xbox_MemoryLayoutInit
#define xbox_memory_shutdown     xbox_MemoryLayoutShutdown
#define xbox_is_xbox_address     xbox_IsXboxAddress
#define xbox_get_memory_base     xbox_GetMemoryBase
#define xbox_get_memory_offset   xbox_GetMemoryOffset
#define xbox_get_mapping_handle  xbox_GetMappingHandle
#define xbox_heap_alloc          xbox_HeapAlloc
#define xbox_heap_free           xbox_HeapFree

#endif /* XBOX_MEMORY_H */
