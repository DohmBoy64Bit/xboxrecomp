# Memory Layout Reproduction

Xbox code uses 32-bit absolute virtual addresses. The shared runtime must preserve
those addresses without embedding any one title's `.text`, `.rdata`, `.data`,
stack, heap, TLS, or kernel-data locations.

## Xbox RAM and address translation

The console has 64 MB of unified RAM. The runtime creates one page-file-backed
64 MB object and maps a base view plus mirror views at 64 MB intervals. Every
view aliases the same pages, so a write through a mirrored Xbox address is visible
through the base view.

The host may not grant Xbox VA zero as the native mapping base. Recompiled memory
access therefore uses a runtime offset:

```c
#define XBOX_PTR(address) \
    ((uintptr_t)(uint32_t)(address) + g_xbox_mem_offset)
#define MEM8(address)  (*(volatile uint8_t  *)XBOX_PTR(address))
#define MEM16(address) (*(volatile uint16_t *)XBOX_PTR(address))
#define MEM32(address) (*(volatile uint32_t *)XBOX_PTR(address))
```

The `uint32_t` conversion is required because original Xbox arithmetic wraps at
32 bits before conversion to the host pointer width.

## Exact-XBE section loading

`xbox_MemoryLayoutInit()` validates the XBE magic, image range, header size,
section table, every section virtual range, and every raw range. It then:

1. copies the XBE image header to its Xbox base address;
2. zeroes each section's complete virtual size;
3. copies the bounded initialized bytes from the XBE;
4. retains original executable bytes for game-side scanners and pointer tables;
5. rejects malformed ranges instead of skipping them silently.

No shared header contains title-specific section constants. The parser JSON and
target profile provide build-time identity; the runtime independently parses the
exact loaded XBE.

## Runtime-owned ranges

The XBE header and every section are treated as occupied Xbox VA ranges. The
initializer sorts and merges them, then searches all remaining 64 MB gaps for the
largest candidate that can hold:

- a 4 KB kernel-data export area;
- an 8 MB simulated stack; and
- at least a 4 MB runtime heap.

The selected addresses are exposed only after successful initialization:

```c
XBOX_KERNEL_DATA_BASE
XBOX_STACK_BASE
XBOX_STACK_TOP
XBOX_HEAP_BASE
XBOX_HEAP_SIZE
```

If no verified gap can satisfy the requirements, initialization fails. It never
falls back to a Burnout 3, Dashboard, or other reference-title address.

## Kernel thunk and kernel version identity

The entry-point encoding determines whether retail or debug XOR keys apply. The
runtime decodes the corresponding kernel-thunk address, checks that it is aligned
and inside Xbox RAM, then validates a zero-terminated sequence of
`0x80000000 | ordinal` entries. The bridge refuses to initialize without this
exact target table.

The emulated kernel version is populated from the XBE's kernel library-version
entry when present. A reference title's XDK build is not used as a default.

## Low-memory thread state

The lifter models `fs:[offset]` accesses as low Xbox memory. The runtime initializes
only shared fields:

```text
fs:[0x00]  end of SEH chain
fs:[0x04]  runtime-selected stack top
fs:[0x08]  runtime-selected stack base
fs:[0x18]  self pointer for the emulated low-memory TIB
fs:[0x20]  neutral KPCR/Prcb placeholder
fs:[0x28]  target-specific context, zero by default
```

A project may call `xbox_MemoryLayoutSetFs28Context()` only after static or runtime
evidence identifies the correct context VA for the exact binary. The shared
runtime does not create a fake RenderWare context in a reference title's BSS.

## Heap behavior

The current heap is a zero-filling bump allocator over the selected free range.
It returns Xbox VAs, not native pointers. `xbox_HeapFree()` remains a no-op, so
long-running or allocation-heavy targets must validate whether that behavior is
sufficient before claiming parity.

## Fixed platform ranges

Some addresses are platform or runtime architecture, not target configuration:

- Xbox RAM size and 64 MB mirror behavior;
- the Xbox image base convention at `0x00010000`;
- NV2A/PAPU hardware register ranges;
- the fake Xbox kernel PE page used by code that probes kernel headers;
- the synthetic kernel-dispatch range beginning at `0xFE000000`.

Do not move these into a title profile merely because they are hexadecimal values.
Conversely, do not treat a game global or linked-library section as fixed because
it appeared in a reference project.

## Protection policy

The runtime does not independently protect each XBE section. Adjacent sections may
share a host page, so applying read-only protection to one range can accidentally
protect bytes belonging to a writable neighbor. A future protection plan must be
derived page-by-page from the complete target section table.

## Validation checklist

Before runtime bring-up, verify:

- the target profile, parser JSON, and exact XBE agree;
- every loaded section matches the parser coordinates and raw bounds;
- runtime ranges overlap neither the header nor a section;
- the target thunk table was decoded and registered;
- `XBOX_STACK_TOP` and heap bounds are nonzero only after initialization;
- mirror writes are visible through the base view;
- target-specific `fs:[0x28]` state is documented or remains zero;
- shared runtime changes are regression-tested against every available target.

See [Target Profiles](target-profiles.md) and
[Building the Runtime](../pipeline/05-runtime.md).
