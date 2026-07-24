/**
 * Xbox Memory Layout Implementation
 *
 * Maps the XBE data sections to their expected virtual addresses on Windows.
 * This is critical for the recompiled code which references globals by
 * absolute address (e.g., mov eax, [0x004D532C]).
 *
 * Implementation:
 * 1. Create a shared 64 MB Xbox RAM backing store and true mirror views.
 * 2. Parse and validate the exact XBE header and every section range.
 * 3. Copy initialized bytes and zero each section's virtual tail.
 * 4. Select non-overlapping runtime ranges for kernel data, stack, and heap.
 * 5. Decode target-specific kernel metadata without reference-title fallbacks.
 */

#include "xbox_memory_layout.h"
#include "kernel.h"
#include <stdio.h>
#include <string.h>

/* XBE header field offsets (per xboxdevwiki.net/Xbe) */
#define XBE_MAGIC_OFFSET        0x0000
#define XBE_BASE_ADDR_OFFSET    0x0104
#define XBE_HEADER_SIZE_OFFSET  0x0108
#define XBE_SECTION_COUNT_OFFSET 0x011C
#define XBE_SECTION_HEADERS_OFFSET 0x0120
#define XBE_ENTRY_POINT_OFFSET     0x0128
#define XBE_KERNEL_THUNK_OFFSET    0x0158
#define XBE_LIBRARY_COUNT_OFFSET   0x0160
#define XBE_LIBRARY_ADDR_OFFSET    0x0164
#define XBE_KERNEL_LIB_OFFSET      0x0168

#define ENTRY_RETAIL_XOR  0xA8FC57ABu
#define ENTRY_DEBUG_XOR   0x94859D4Bu
#define THUNK_RETAIL_XOR  0x5B6D40B6u
#define THUNK_DEBUG_XOR   0xEFB1F152u

/* XBE section header layout (56 bytes each) */
#define SECTHDR_FLAGS       0x00
#define SECTHDR_VA          0x04
#define SECTHDR_VSIZE       0x08
#define SECTHDR_RAW_OFFSET  0x0C
#define SECTHDR_RAW_SIZE    0x10
#define SECTHDR_NAME_ADDR   0x14
#define SECTHDR_SIZE        56

static void *g_memory_base = NULL;
static size_t g_memory_size = 0;
static ptrdiff_t g_memory_offset = 0;  /* actual_base - XBOX_BASE_ADDRESS */

uint32_t g_xbox_kernel_data_base = 0;
uint32_t g_xbox_stack_base = 0;
uint32_t g_xbox_stack_top = 0;
uint32_t g_xbox_heap_base = 0;
uint32_t g_xbox_heap_size = 0;

static uint32_t g_fs28_context_va = 0;
static uint32_t g_heap_next = 0;

/* File mapping handle for the Xbox memory region.
 * Using CreateFileMapping + MapViewOfFileEx allows mirror views to alias
 * the same physical pages as the base region, so writes to mirror addresses
 * (which wrap modulo 64 MB on real Xbox hardware) correctly modify the
 * underlying data. */
static HANDLE g_mapping_handle = NULL;

/* Mirror view pointers for cleanup */
static void *g_mirror_views[XBOX_NUM_MIRRORS] = {0};

/* Separate allocation for Xbox kernel address space (0x80010000+).
 * Some RenderWare code reads the kernel PE header to detect features. */
static void *g_kernel_memory = NULL;

/* Global offset accessible by recompiled code (via recomp_types.h) */
ptrdiff_t g_xbox_mem_offset = 0;

/* Global registers for recompiled code (via recomp_types.h) */
uint32_t g_eax = 0, g_ecx = 0, g_edx = 0, g_esp = 0;
uint32_t g_ebx = 0, g_esi = 0, g_edi = 0;

/* SEH frame pointer bridge (see recomp_types.h for explanation) */
uint32_t g_seh_ebp = 0;

/* ICALL trace ring buffer */
volatile uint32_t g_icall_trace[16] = {0};
volatile uint32_t g_icall_trace_idx = 0;
volatile uint64_t g_icall_count = 0;

typedef struct _XBOX_VA_RANGE {
    uint32_t start;
    uint32_t end;
} XBOX_VA_RANGE;

static uint32_t align_up_u32(uint32_t value, uint32_t alignment)
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static void sort_ranges(XBOX_VA_RANGE *ranges, uint32_t count)
{
    for (uint32_t i = 1; i < count; i++) {
        XBOX_VA_RANGE value = ranges[i];
        uint32_t j = i;
        while (j > 0 && ranges[j - 1].start > value.start) {
            ranges[j] = ranges[j - 1];
            j--;
        }
        ranges[j] = value;
    }
}

static void consider_runtime_gap(
    uint32_t gap_start,
    uint32_t gap_end,
    uint32_t *best_start,
    uint32_t *best_end)
{
    const uint32_t minimum_heap_size = 4u * 1024u * 1024u;
    const uint32_t alignment = 0x10000u;
    uint32_t kernel_base;
    uint32_t stack_base;
    uint32_t heap_base;
    uint32_t candidate_heap_size;
    uint32_t current_heap_size = 0;

    if (gap_start >= gap_end) {
        return;
    }
    kernel_base = align_up_u32(gap_start, alignment);
    if (kernel_base >= gap_end) {
        return;
    }
    stack_base = align_up_u32(kernel_base + XBOX_KERNEL_DATA_SIZE, alignment);
    if (stack_base > UINT32_MAX - XBOX_STACK_SIZE) {
        return;
    }
    heap_base = stack_base + XBOX_STACK_SIZE;
    if (heap_base > gap_end || gap_end - heap_base < minimum_heap_size) {
        return;
    }
    candidate_heap_size = gap_end - heap_base;
    if (*best_end != 0) {
        uint32_t current_stack_base = align_up_u32(
            *best_start + XBOX_KERNEL_DATA_SIZE, alignment);
        uint32_t current_heap_base = current_stack_base + XBOX_STACK_SIZE;
        current_heap_size = *best_end - current_heap_base;
    }
    if (*best_end == 0 || candidate_heap_size > current_heap_size) {
        *best_start = kernel_base;
        *best_end = gap_end;
    }
}

static BOOL configure_runtime_layout(XBOX_VA_RANGE *occupied, uint32_t count)
{
    uint32_t cursor = XBOX_MAP_START;
    uint32_t best_start = 0;
    uint32_t best_end = 0;

    sort_ranges(occupied, count);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t start = occupied[i].start;
        uint32_t end = occupied[i].end;
        if (start > XBOX_TOTAL_RAM) {
            start = XBOX_TOTAL_RAM;
        }
        if (end > XBOX_TOTAL_RAM) {
            end = XBOX_TOTAL_RAM;
        }
        if (start > cursor) {
            consider_runtime_gap(cursor, start, &best_start, &best_end);
        }
        if (end > cursor) {
            cursor = end;
        }
    }
    if (cursor < XBOX_TOTAL_RAM) {
        consider_runtime_gap(cursor, XBOX_TOTAL_RAM, &best_start, &best_end);
    }
    if (best_end == 0) {
        fprintf(stderr,
                "xbox_MemoryLayoutInit: no free Xbox RAM gap can hold kernel "
                "data, the %u MB simulated stack, and a 4 MB minimum heap\n",
                XBOX_STACK_SIZE / (1024u * 1024u));
        return FALSE;
    }

    g_xbox_kernel_data_base = best_start;
    g_xbox_stack_base = align_up_u32(
        g_xbox_kernel_data_base + XBOX_KERNEL_DATA_SIZE, 0x10000u);
    g_xbox_stack_top = g_xbox_stack_base + XBOX_STACK_SIZE - 16u;
    g_xbox_heap_base = g_xbox_stack_base + XBOX_STACK_SIZE;
    g_xbox_heap_size = best_end - g_xbox_heap_base;
    g_heap_next = g_xbox_heap_base;
    return TRUE;
}

static uint32_t validate_thunk_candidate(uint32_t thunk_va)
{
    uint32_t count = 0;

    if (thunk_va < XBOX_BASE_ADDRESS ||
        thunk_va > XBOX_TOTAL_RAM - XBOX_KERNEL_MAX_THUNK_SLOTS * 4u ||
        (thunk_va & 3u) != 0) {
        return 0;
    }

    for (uint32_t slot = 0; slot < XBOX_KERNEL_MAX_THUNK_SLOTS; slot++) {
        uint32_t entry = *(volatile uint32_t *)
            ((uintptr_t)(thunk_va + slot * 4u) + g_memory_offset);
        if (entry == 0) {
            return count;
        }
        if ((entry & 0x80000000u) == 0 ||
            (entry & 0x7FFFFFFFu) == 0 ||
            (entry & 0x7FFFFFFFu) > XBOX_KERNEL_MAX_ORDINAL) {
            return 0;
        }
        count++;
    }
    return count;
}

static BOOL configure_target_thunks(const uint8_t *xbe, size_t xbe_size)
{
    uint32_t entry_raw;
    uint32_t thunk_raw;
    uint32_t base_addr;
    uint32_t image_size;
    uint32_t retail_entry;
    uint32_t debug_entry;
    uint32_t thunk_va;
    uint32_t thunk_count;
    BOOL is_debug;

    if (xbe_size < XBE_KERNEL_THUNK_OFFSET + sizeof(uint32_t)) {
        return FALSE;
    }

    base_addr = *(const uint32_t *)(xbe + XBE_BASE_ADDR_OFFSET);
    image_size = *(const uint32_t *)(xbe + 0x010C);
    if (base_addr < XBOX_BASE_ADDRESS || image_size == 0 ||
        base_addr > XBOX_TOTAL_RAM - image_size) {
        fprintf(stderr, "xbox_MemoryLayoutInit: invalid XBE image range\n");
        return FALSE;
    }
    entry_raw = *(const uint32_t *)(xbe + XBE_ENTRY_POINT_OFFSET);
    thunk_raw = *(const uint32_t *)(xbe + XBE_KERNEL_THUNK_OFFSET);
    retail_entry = entry_raw ^ ENTRY_RETAIL_XOR;
    debug_entry = entry_raw ^ ENTRY_DEBUG_XOR;

    if (retail_entry >= base_addr && retail_entry < base_addr + image_size) {
        is_debug = FALSE;
    } else if (debug_entry >= base_addr && debug_entry < base_addr + image_size) {
        is_debug = TRUE;
    } else {
        fprintf(stderr, "xbox_MemoryLayoutInit: cannot identify XBE retail/debug encoding\n");
        return FALSE;
    }

    thunk_va = thunk_raw ^ (is_debug ? THUNK_DEBUG_XOR : THUNK_RETAIL_XOR);
    thunk_count = validate_thunk_candidate(thunk_va);
    if (thunk_count == 0) {
        fprintf(stderr,
                "xbox_MemoryLayoutInit: invalid %s kernel thunk table at 0x%08X\n",
                is_debug ? "debug" : "retail", thunk_va);
        return FALSE;
    }

    xbox_kernel_set_thunk_address(thunk_va, thunk_count);
    fprintf(stderr, "  Kernel thunks: %u entries at Xbox VA 0x%08X (%s)\n",
            thunk_count, thunk_va, is_debug ? "debug" : "retail");
    return TRUE;
}

static void configure_target_kernel_version(const uint8_t *xbe, size_t xbe_size)
{
    uint32_t base_addr;
    uint32_t kernel_version_va;
    uint32_t kernel_version_off;

    if (xbe_size < XBE_KERNEL_LIB_OFFSET + sizeof(uint32_t)) {
        return;
    }

    base_addr = *(const uint32_t *)(xbe + XBE_BASE_ADDR_OFFSET);
    kernel_version_va = *(const uint32_t *)(xbe + XBE_KERNEL_LIB_OFFSET);
    if (kernel_version_va < base_addr) {
        return;
    }
    kernel_version_off = kernel_version_va - base_addr;
    if (kernel_version_off + 16u > xbe_size) {
        return;
    }

    xbox_kernel_set_version(
        *(const uint16_t *)(xbe + kernel_version_off + 8u),
        *(const uint16_t *)(xbe + kernel_version_off + 10u),
        *(const uint16_t *)(xbe + kernel_version_off + 12u),
        *(const uint16_t *)(xbe + kernel_version_off + 14u) & 0x1FFFu);
}

BOOL xbox_MemoryLayoutInit(const void *xbe_data, size_t xbe_size)
{
    DWORD old_protect;
    const uint8_t *xbe = (const uint8_t *)xbe_data;

    if (g_memory_base) {
        fprintf(stderr, "xbox_MemoryLayoutInit: already initialized\n");
        return FALSE;
    }
    if (!xbe || xbe_size < 0x0178 || memcmp(xbe + XBE_MAGIC_OFFSET, "XBEH", 4) != 0) {
        fprintf(stderr, "xbox_MemoryLayoutInit: invalid or truncated XBE input\n");
        return FALSE;
    }

    xbox_kernel_set_thunk_address(0, 0);

    /*
     * Calculate the full range we need to map.
     * From XBOX_MAP_START (0x0) to the end of the furthest section.
     * This includes low memory (KPCR at 0x0-0xFF) which game code reads
     * from, the XBE sections, and the simulated stack.
     */
    /* Map the full 64MB Xbox address space (covers all sections + stack + heap) */
    g_memory_size = XBOX_TOTAL_RAM;

    /*
     * Create a file mapping backed by the page file.
     *
     * Using file mapping instead of VirtualAlloc allows us to map the same
     * physical pages at multiple virtual addresses via MapViewOfFileEx.
     * This is critical for the Xbox RAM mirror: the Xbox memory controller
     * uses a 26-bit address bus, so ALL addresses wrap modulo 64 MB.
     * Code that writes to address 0x20000448 is really writing to 0x00000448.
     * With file mapping views, we create aliased mappings at 64 MB intervals
     * that all point to the same physical memory.
     */
    g_mapping_handle = CreateFileMappingA(
        INVALID_HANDLE_VALUE,   /* page file backed */
        NULL,                   /* default security */
        PAGE_READWRITE,         /* read-write access */
        0,                      /* high DWORD of size */
        (DWORD)g_memory_size,   /* low DWORD of size (64 MB) */
        NULL                    /* unnamed mapping */
    );
    if (!g_mapping_handle) {
        fprintf(stderr, "xbox_MemoryLayoutInit: CreateFileMapping failed (error %u)\n",
                (unsigned int)GetLastError());
        return FALSE;
    }

    /*
     * Map the base view at the desired virtual address.
     * Try the original Xbox base address first. If that fails (common on
     * Windows 11 where low addresses are often reserved), try page-aligned
     * addresses upward until we find a free region.
     */
    {
        static const uintptr_t try_bases[] = {
            XBOX_BASE_ADDRESS,      /* 0x00010000 - original Xbox address */
            0x00800000,             /* 8 MB - above typical PEB/TEB region */
            0x01000000,             /* 16 MB */
            0x02000000,             /* 32 MB */
            0x10000000,             /* 256 MB */
            0,                      /* sentinel - let OS choose */
        };

        const size_t try_base_count = sizeof(try_bases) / sizeof(try_bases[0]);

        for (size_t i = 0; i < try_base_count; i++) {
            LPVOID hint = try_bases[i] ? (LPVOID)try_bases[i] : NULL;
            g_memory_base = MapViewOfFileEx(
                g_mapping_handle,
                FILE_MAP_ALL_ACCESS,
                0, 0,           /* offset into mapping */
                g_memory_size,  /* size */
                hint            /* desired base address or NULL */
            );
            if (g_memory_base) {
                if (try_bases[i] != 0 && (uintptr_t)g_memory_base != try_bases[i]) {
                    /* OS gave us a different address for a fixed hint, retry. */
                    UnmapViewOfFile(g_memory_base);
                    g_memory_base = NULL;
                    continue;
                }
                break;
            }
        }
    }

    if (!g_memory_base) {
        fprintf(stderr, "xbox_MemoryLayoutInit: failed to map base view (%zu KB)\n",
                g_memory_size / 1024);
        CloseHandle(g_mapping_handle);
        g_mapping_handle = NULL;
        return FALSE;
    }

    g_memory_offset = (uintptr_t)g_memory_base - XBOX_MAP_START;

    if (g_memory_offset == 0) {
        fprintf(stderr, "xbox_MemoryLayoutInit: mapped %zu KB at 0x%08X (original Xbox address)\n",
                g_memory_size / 1024, XBOX_MAP_START);
    } else {
        fprintf(stderr, "xbox_MemoryLayoutInit: mapped %zu KB at 0x%p (offset %+td from Xbox base)\n",
                g_memory_size / 1024, g_memory_base, g_memory_offset);
    }

    /*
     * Helper macro: convert Xbox VA to actual mapped address.
     * When g_memory_offset == 0 (ideal case), this is identity.
     */
    #define XBOX_VA(va) ((void *)((uintptr_t)(va) + g_memory_offset))

    /*
     * Copy XBE header to base address.
     * The Xbox kernel maps the XBE image header at 0x00010000.
     * Game code reads kernel thunk table, certificate data, and
     * section info from this region.
     */
    {
        /* XBE header size is at file offset 0x0108 (SizeOfImageHeader) */
        DWORD header_size = 0;
        if (xbe_size >= 0x10C) {
            header_size = *(const DWORD *)(xbe + 0x0108);
        }
        if (header_size == 0 || header_size > 0x10000)
            header_size = 0x1000;  /* fallback: 4KB */
        if (header_size > xbe_size)
            header_size = (DWORD)xbe_size;
        memcpy(XBOX_VA(XBOX_BASE_ADDRESS), xbe, header_size);
        fprintf(stderr, "  XBE header: %u bytes at %p (Xbox VA 0x%08X)\n",
                header_size, XBOX_VA(XBOX_BASE_ADDRESS), XBOX_BASE_ADDRESS);
    }

    /*
     * Dynamically load ALL XBE sections by parsing the section headers.
     *
     * This replaces the old approach of hardcoding section addresses for
     * a specific game (Burnout 3). By reading the section table from the
     * XBE header, any game's sections are loaded automatically.
     *
     * Every section is copied to its original Xbox VA:
     * - .text: needed because memory walkers may scan code pages
     * - .rdata: constants, vtables, kernel thunk table
     * - .data: global variables (initialized portion from XBE, BSS zeroed)
     * - XDK library sections (D3D, DSOUND, WMADEC, XPP, etc.)
     * - DOLBY, BINK, XTIMAGE, etc.
     */
    {
        DWORD base_addr = *(const DWORD *)(xbe + XBE_BASE_ADDR_OFFSET);
        DWORD num_sections = *(const DWORD *)(xbe + XBE_SECTION_COUNT_OFFSET);
        DWORD sect_headers_va = *(const DWORD *)(xbe + XBE_SECTION_HEADERS_OFFSET);
        DWORD sect_headers_off = sect_headers_va - base_addr;
        int sections_loaded = 0;
        size_t total_bytes = 0;
        XBOX_VA_RANGE occupied[65];
        uint32_t occupied_count = 1;
        DWORD header_size = *(const DWORD *)(xbe + XBE_HEADER_SIZE_OFFSET);

        if (header_size == 0 || header_size > xbe_size ||
            base_addr > XBOX_TOTAL_RAM - header_size) {
            fprintf(stderr, "xbox_MemoryLayoutInit: invalid XBE header size\n");
            xbox_MemoryLayoutShutdown();
            return FALSE;
        }
        occupied[0].start = XBOX_MAP_START;
        occupied[0].end = base_addr + header_size;

        if (num_sections == 0 || num_sections > 64 ||
            sect_headers_va < base_addr ||
            sect_headers_off + num_sections * SECTHDR_SIZE > xbe_size) {
            fprintf(stderr, "xbox_MemoryLayoutInit: invalid XBE section table\n");
            xbox_MemoryLayoutShutdown();
            return FALSE;
        }

        for (DWORD si = 0; si < num_sections; si++) {
            const uint8_t *sh = xbe + sect_headers_off + si * SECTHDR_SIZE;
            DWORD sec_va = *(const DWORD *)(sh + SECTHDR_VA);
            DWORD sec_vsize = *(const DWORD *)(sh + SECTHDR_VSIZE);
            if (sec_vsize == 0 || sec_va < XBOX_BASE_ADDRESS ||
                sec_va > XBOX_TOTAL_RAM - sec_vsize) {
                fprintf(stderr, "xbox_MemoryLayoutInit: invalid section %u virtual range\n", si);
                xbox_MemoryLayoutShutdown();
                return FALSE;
            }
            occupied[occupied_count].start = sec_va;
            occupied[occupied_count].end = sec_va + sec_vsize;
            occupied_count++;
        }

        if (!configure_runtime_layout(occupied, occupied_count)) {
            xbox_MemoryLayoutShutdown();
            return FALSE;
        }

        fprintf(stderr, "  XBE sections: %u (headers at file offset 0x%08X)\n",
                num_sections, sect_headers_off);
        fprintf(stderr,
                "  Runtime layout: kernel-data=0x%08X stack=0x%08X-0x%08X "
                "heap=0x%08X-0x%08X\n",
                XBOX_KERNEL_DATA_BASE, XBOX_STACK_BASE, XBOX_STACK_TOP,
                XBOX_HEAP_BASE, XBOX_HEAP_BASE + XBOX_HEAP_SIZE);

        for (DWORD si = 0; si < num_sections; si++) {

            const uint8_t *sh = xbe + sect_headers_off + si * SECTHDR_SIZE;
            DWORD sec_va       = *(const DWORD *)(sh + SECTHDR_VA);
            DWORD sec_vsize    = *(const DWORD *)(sh + SECTHDR_VSIZE);
            DWORD sec_raw_off  = *(const DWORD *)(sh + SECTHDR_RAW_OFFSET);
            DWORD sec_raw_size = *(const DWORD *)(sh + SECTHDR_RAW_SIZE);
            DWORD sec_name_va  = *(const DWORD *)(sh + SECTHDR_NAME_ADDR);

            /* Read section name from XBE header */
            const char *sec_name = "?";
            DWORD name_off = sec_name_va - base_addr;
            if (name_off < xbe_size && name_off + 8 <= xbe_size)
                sec_name = (const char *)(xbe + name_off);

            if (sec_raw_size > 0 &&
                (sec_raw_off > xbe_size || sec_raw_size > xbe_size - sec_raw_off)) {
                fprintf(stderr, "xbox_MemoryLayoutInit: section %u exceeds XBE bytes\n", si);
                xbox_MemoryLayoutShutdown();
                return FALSE;
            }

            /* Determine copy size (raw_size may exceed vsize due to alignment) */
            DWORD copy_size = (sec_raw_size < sec_vsize) ? sec_raw_size : sec_vsize;

            /* Zero the full virtual size first (handles BSS) */
            memset(XBOX_VA(sec_va), 0, sec_vsize);

            /* Copy initialized data from XBE */
            if (copy_size > 0 && sec_raw_off + copy_size <= xbe_size) {
                memcpy(XBOX_VA(sec_va), xbe + sec_raw_off, copy_size);
            }

            sections_loaded++;
            total_bytes += copy_size;

            fprintf(stderr, "  [%2u] %-12s VA=0x%08X vsize=%-8u raw=0x%08X rsize=%-8u%s\n",
                    si, sec_name, sec_va, sec_vsize, sec_raw_off, sec_raw_size,
                    (sec_raw_size < sec_vsize) ? " (BSS)" : "");
        }

        fprintf(stderr, "  Loaded %d/%u sections (%zu bytes total)\n",
                sections_loaded, num_sections, total_bytes);
    }

    if (!configure_target_thunks(xbe, xbe_size)) {
        xbox_MemoryLayoutShutdown();
        return FALSE;
    }
    configure_target_kernel_version(xbe, xbe_size);

    /*
     * Section protections are not applied piecemeal here. Adjacent XBE sections
     * may share host pages, so title-neutral protection requires a page-aware
     * plan derived from the complete section table rather than reference-title
     * boundaries.
     */
    (void)old_protect;

    #undef XBOX_VA

    /* Set the global offset for recompiled code MEM macros */
    g_xbox_mem_offset = g_memory_offset;

    /*
     * Initialize the Xbox stack for recompiled code.
     * The stack area lives at XBOX_STACK_BASE in Xbox address space.
     * g_esp is the global stack pointer shared by all translated functions.
     */
    g_esp = XBOX_STACK_TOP;
    fprintf(stderr, "  Stack: %u KB at Xbox VA 0x%08X (ESP = 0x%08X)\n",
            XBOX_STACK_SIZE / 1024, XBOX_STACK_BASE, g_esp);

    /*
     * Populate the fake Thread Information Block (TIB) at Xbox VA 0x0.
     *
     * The original Xbox code uses fs:[offset] to read per-thread data,
     * but the recompiler drops the fs: segment prefix and generates
     * MEM32(offset) instead. Since we mapped low memory (0x0-0xFFFF),
     * we populate the TIB fields that game code accesses:
     *
     *   fs:[0x00] = SEH exception list (-1 = end of chain)
     *   fs:[0x04] = stack base (top of stack)
     *   fs:[0x08] = stack limit (bottom of stack)
     *   fs:[0x18] = self pointer (TIB address)
     *   fs:[0x20] = KPCR Prcb pointer (→ fake structure)
     *   fs:[0x28] = TLS / RW engine context pointer
     *
     * Shared fields are initialized only from target-neutral runtime state.
     */
    {
        #define XBOX_VA(va) ((void *)((uintptr_t)(va) + g_memory_offset))
        #define MEM32_INIT(va, val) (*(uint32_t *)XBOX_VA(va) = (uint32_t)(val))

        /* Fake TIB at address 0x0 */
        MEM32_INIT(0x00, 0xFFFFFFFF);       /* SEH: end of chain */
        MEM32_INIT(0x04, XBOX_STACK_TOP);   /* Stack base (high address) */
        MEM32_INIT(0x08, XBOX_STACK_BASE);  /* Stack limit (low address) */
        MEM32_INIT(0x18, 0x00000000);       /* Self pointer (TIB at VA 0) */

        /*
         * fs:[0x20] - On Xbox KPCR, this is the Prcb pointer.
         * Game code reads [fs:[0x20] + 0x250] which on the real Xbox
         * accesses a D3D cache structure. We set it to 0 so the read
         * at offset 0x250 returns 0, causing the cache init to be skipped.
         */
        MEM32_INIT(0x20, 0x00000000);

        /* fs:[0x28] is target-specific. Leave it zero unless the target
         * supplies an evidence-backed context VA through the public setter. */
        MEM32_INIT(0x28, g_fs28_context_va);

        fprintf(stderr, "  TIB: emulated at VA 0x0, fs:[0x28]=0x%08X\n",
                g_fs28_context_va);
        #undef MEM32_INIT
        #undef XBOX_VA
    }

    /*
     * Allocate a page at Xbox kernel address space (0x80010000).
     *
     * RenderWare's Xbox driver code (xbcache.c) reads MEM32(0x8001003C)
     * to parse the Xbox kernel's PE header and find the INIT section for
     * CPU cache line sizing. On PC, we provide a minimal fake PE header
     * with 0 sections so the function gracefully skips the cache init.
     *
     * The actual native address is 0x80010000 + g_memory_offset.
     */
    {
        #define XBOX_KERNEL_BASE 0x80010000u
        #define KERNEL_PAGE_SIZE 4096
        uintptr_t kernel_native = XBOX_KERNEL_BASE + g_memory_offset;
        g_kernel_memory = VirtualAlloc(
            (LPVOID)kernel_native,
            KERNEL_PAGE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        if (g_kernel_memory) {
            /* Zero-fill then set e_lfanew = 0x80 (offset to PE header).
             * With the rest zeroed, NumberOfSections = 0 and the INIT
             * section search finds nothing, which is the safe path. */
            memset(g_kernel_memory, 0, KERNEL_PAGE_SIZE);
            *(uint32_t *)((uint8_t *)g_kernel_memory + 0x3C) = 0x80;  /* e_lfanew */
            fprintf(stderr, "  Kernel: fake PE header at Xbox VA 0x%08X (native %p)\n",
                    XBOX_KERNEL_BASE, g_kernel_memory);
        } else {
            fprintf(stderr, "  WARNING: could not map Xbox kernel VA 0x%08X\n",
                    XBOX_KERNEL_BASE);
        }
        #undef XBOX_KERNEL_BASE
        #undef KERNEL_PAGE_SIZE
    }

    /* Initialize the dynamic heap. */
    fprintf(stderr, "  Heap: %u MB at Xbox VA 0x%08X-0x%08X\n",
            XBOX_HEAP_SIZE / (1024 * 1024), XBOX_HEAP_BASE,
            XBOX_HEAP_BASE + XBOX_HEAP_SIZE);

    /*
     * Map mirror views of the 64 MB region.
     *
     * On retail Xbox, physical RAM wraps at 64 MB due to the 26-bit
     * address bus. Address 0x04070000 reads the same data as 0x00070000.
     * The RenderWare engine's memory walker crosses 64 MB and accesses
     * mirrored data for an extended walk covering 256+ MB of virtual
     * addresses. Game init code also writes large data structures past
     * 64 MB that on real hardware wrap into physical RAM.
     *
     * We map additional views of the SAME file mapping section at 64 MB
     * intervals. All views alias the same physical pages, so reads and
     * writes at any mirror address correctly access the base data.
     */
    {
        int mirrors_ok = 0;
        for (int m = 0; m < XBOX_NUM_MIRRORS; m++) {
            uintptr_t mirror_base = (uintptr_t)g_memory_base +
                                    (uintptr_t)(m + 1) * g_memory_size;
            g_mirror_views[m] = MapViewOfFileEx(
                g_mapping_handle,
                FILE_MAP_ALL_ACCESS,
                0, 0,
                g_memory_size,
                (LPVOID)mirror_base
            );
            if (g_mirror_views[m]) {
                mirrors_ok++;
            } else {
                fprintf(stderr, "  Mirror %d: FAILED at %p (error %u)\n",
                        m + 1, (void *)mirror_base,
                        (unsigned int)GetLastError());
            }
        }
        fprintf(stderr, "  RAM mirror: %d/%d views mapped (covers %d MB)\n",
                mirrors_ok, XBOX_NUM_MIRRORS,
                (int)((mirrors_ok + 1) * g_memory_size / (1024 * 1024)));
    }

    fprintf(stderr, "xbox_MemoryLayoutInit: complete\n");
    return TRUE;
}

void xbox_MemoryLayoutShutdown(void)
{
    if (g_kernel_memory) {
        VirtualFree(g_kernel_memory, 0, MEM_RELEASE);
        g_kernel_memory = NULL;
    }
    /* Unmap mirror views first */
    for (int m = 0; m < XBOX_NUM_MIRRORS; m++) {
        if (g_mirror_views[m]) {
            UnmapViewOfFile(g_mirror_views[m]);
            g_mirror_views[m] = NULL;
        }
    }
    /* Unmap base view */
    if (g_memory_base) {
        UnmapViewOfFile(g_memory_base);
        g_memory_base = NULL;
        g_memory_size = 0;
    }
    /* Close file mapping handle */
    if (g_mapping_handle) {
        CloseHandle(g_mapping_handle);
        g_mapping_handle = NULL;
    }
    g_memory_offset = 0;
    g_xbox_mem_offset = 0;
    g_xbox_kernel_data_base = 0;
    g_xbox_stack_base = 0;
    g_xbox_stack_top = 0;
    g_xbox_heap_base = 0;
    g_xbox_heap_size = 0;
    g_heap_next = 0;
    xbox_kernel_set_thunk_address(0, 0);
    fprintf(stderr, "xbox_MemoryLayoutShutdown: released\n");
}

BOOL xbox_IsXboxAddress(uintptr_t address)
{
    return (address >= XBOX_BASE_ADDRESS &&
            address < XBOX_BASE_ADDRESS + g_memory_size);
}

void *xbox_GetMemoryBase(void)
{
    return g_memory_base;
}

ptrdiff_t xbox_GetMemoryOffset(void)
{
    return g_memory_offset;
}

void xbox_MemoryLayoutSetFs28Context(uint32_t context_va)
{
    g_fs28_context_va = context_va;
    if (g_memory_base) {
        *(uint32_t *)((uintptr_t)0x28u + g_memory_offset) = context_va;
    }
}

/* ── Dynamic heap allocator ────────────────────────────────
 *
 * Simple bump allocator for MmAllocateContiguousMemory and similar.
 * Returns Xbox VAs within the mapped region so MEM32() works correctly.
 * No free support (bump-only for now).
 */
static int g_heap_alloc_count = 0;

uint32_t xbox_HeapAlloc(uint32_t size, uint32_t alignment)
{
    uint32_t result;

    if (g_xbox_heap_base == 0 || g_xbox_heap_size == 0) {
        fprintf(stderr, "xbox_HeapAlloc: memory layout is not initialized\n");
        return 0;
    }
    if (alignment < 4) alignment = 4;

    /* Enforce minimum allocation size.
     * The Xbox D3D8 code sometimes computes resource sizes from GPU
     * capabilities that return 0 (since we don't have real NV2A hardware),
     * resulting in zero-size allocations. With a bump allocator, these all
     * return the same address, causing overlapping structures. Enforce a
     * minimum of 4096 bytes so each allocation gets its own memory. */
    if (size < 4096) size = 4096;

    /* Align the next pointer */
    result = (g_heap_next + alignment - 1) & ~(alignment - 1);

    if (result + size > XBOX_HEAP_BASE + XBOX_HEAP_SIZE) {
        fprintf(stderr, "xbox_HeapAlloc: out of memory (requested %u, used %u/%u)\n",
                size, g_heap_next - XBOX_HEAP_BASE, XBOX_HEAP_SIZE);
        return 0;
    }

    g_heap_next = result + size;

    /* Zero-fill the allocated block (Xbox memory is always zeroed) */
    memset((void *)((uintptr_t)result + g_memory_offset), 0, size);

    g_heap_alloc_count++;
    fprintf(stderr, "  [HEAP] #%d: size=%u align=%u → 0x%08X..0x%08X (used %u/%u)\n",
            g_heap_alloc_count, size, alignment, result, result + size,
            g_heap_next - XBOX_HEAP_BASE, XBOX_HEAP_SIZE);
    fflush(stderr);

    return result;
}

void xbox_HeapFree(uint32_t xbox_va)
{
    /* No-op for bump allocator */
    (void)xbox_va;
}

HANDLE xbox_GetMappingHandle(void)
{
    return g_mapping_handle;
}
