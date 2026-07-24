# xbox_kernel — Xbox kernel replacement layer

The kernel layer maps the exact target XBE into emulated Xbox RAM and replaces
kernel imports with host implementations. Target addresses are decoded from the
current XBE or supplied by its validated target profile; this directory must not
contain a default game section map, entry point, stack address, heap address, or
kernel-thunk address.

## Main components

| Area | Files | Responsibility |
|---|---|---|
| Public ABI | `kernel.h` | Xbox/NT types, constants, export limits, and public APIs |
| Memory | `xbox_memory_layout.c`, `xbox_memory_layout.h` | 64 MB backing store, mirror aliases, exact XBE section loading, runtime free-gap allocation |
| Dispatch | `kernel_bridge.c`, `kernel_thunks.c` | Per-title thunk validation, ordinal dispatch, synthetic kernel VAs, data exports |
| Files and paths | `kernel_file.c`, `kernel_path.c` | NT-style file operations and Xbox-to-host path translation |
| Threads and synchronization | `kernel_thread.c`, `kernel_sync.c` | Thread creation, waits, events, semaphores, mutexes, and critical sections |
| Memory services | `kernel_memory.c`, `kernel_pool.c` | Xbox allocation APIs and the runtime-selected heap |
| Supporting services | `kernel_rtl.c`, `kernel_hal.c`, `kernel_crypto.c`, `kernel_ob.c`, `kernel_io.c`, `kernel_xbox.c` | RTL, hardware, crypto, objects, I/O, and miscellaneous Xbox APIs |

## Target-neutral memory initialization

`xbox_MemoryLayoutInit()` performs the target-dependent work at runtime:

1. Creates the 64 MB Xbox RAM backing mapping and true 64 MB mirror aliases.
2. Validates the XBE header and section table.
3. Copies every valid section to its linked Xbox virtual address and zeroes BSS tails.
4. Decodes and validates the target kernel-thunk table.
5. Reads compatible kernel-version metadata from the target XBE.
6. Searches verified gaps outside the XBE header and all loaded sections for:
   - kernel data exports,
   - the 8 MB simulated stack,
   - and a runtime heap of at least 4 MB.
7. Initializes the low-memory TIB/KPCR compatibility fields.

No game should edit `xbox_memory_layout.h` to insert its section addresses.
The source of truth is the exact XBE plus its parser-validated target profile.

```c
if (!xbox_MemoryLayoutInit(xbe_data, xbe_size)) {
    /* Invalid XBE, overlapping/out-of-range sections, bad thunk table,
       or no safe runtime allocation gap. */
    return 1;
}

g_xbox_mem_offset = xbox_GetMemoryOffset();
g_esp = XBOX_STACK_TOP;
```

The runtime-selected locations are exposed only after successful initialization:

```c
extern uint32_t g_xbox_kernel_data_base;
extern uint32_t g_xbox_stack_base;
extern uint32_t g_xbox_stack_top;
extern uint32_t g_xbox_heap_base;
extern uint32_t g_xbox_heap_size;
```

### Mirror requirement

Xbox RAM wraps on a 26-bit physical address bus. The Windows implementation uses
one file mapping with multiple views so mirrored addresses alias the same bytes.
Independent `VirtualAlloc` copies are not equivalent and must not replace this
backing model.

## Kernel thunk table

The table address and populated slot count belong to the current title. The
memory initializer decodes the XBE header, validates the table contents, and
calls:

```c
xbox_kernel_set_thunk_address(thunk_va, thunk_count);
```

The bridge then refuses to initialize unless that exact table is available:

```c
xbox_kernel_init();
if (!xbox_kernel_bridge_init()) {
    return 1;
}
```

The real kernel export directory uses ordinal slots through 378, with known gaps.
Do not confuse the maximum export ordinal with the number of imports in one
title's thunk table. Per-title thunk loops must use the validated active slot
count; ordinal-indexed tables use `XBOX_KERNEL_EXPORT_TABLE_SIZE`.

Function entries are replaced with synthetic dispatch VAs in the reserved
kernel range. Data-export entries point to objects in the runtime-selected
kernel data area.

## Kernel version

`xbox_MemoryLayoutInit()` derives a compatible kernel/XDK version from the
current XBE library metadata and forwards it through `xbox_kernel_set_version()`.
The shared runtime does not claim one reference title's XDK build for all games.
If the metadata is missing or ambiguous, preserve and report that uncertainty.

## File and save paths

Call `xbox_path_init()` with explicit target directories before game file I/O:

```c
xbox_path_init(game_directory, save_directory);
```

If `game_directory` is omitted, the current working directory is used. If
`save_directory` is omitted, a neutral `xboxrecomp/SaveData` host directory is
selected. The shared kernel no longer inserts a Burnout-specific directory name.

Representative translations are:

```text
\Device\CdRom0\Data\foo.dat -> <game_directory>/Data/foo.dat
D:\Data\foo.dat              -> <game_directory>/Data/foo.dat
T:\save.dat                  -> <save_directory>/save.dat
Z:\cache.dat                 -> <save_directory>/cache/cache.dat
```

Path behavior is platform-specific; validate it on every supported host and
launch from the documented working directory.

## Target-specific low-memory context

The emulated `fs:[0x28]` field defaults to zero. A title may set it only from
evidence obtained for that exact XBE:

```c
xbox_MemoryLayoutSetFs28Context(target_context_va);
```

Do not copy a RenderWare or other engine context address from a reference title.

## Runtime expectations

- Thread entry VAs must resolve through the selected target dispatch table.
- Shared kernel edits require cross-target regression testing.
- A successfully bridged ordinal is not proof that its behavior matches the
  Xbox kernel; accepting stubs and partial implementations must remain visible.
- Do not hide title-owned SEH, invalid ICALLs, or memory corruption with broad
  exception handling.
- Preserve the exact XBE hash, parser analysis, target profile, build identity,
  and runtime logs for every result.

See also:

- [`../../docs/technical/target-profiles.md`](../../docs/technical/target-profiles.md)
- [`../../docs/technical/memory-layout.md`](../../docs/technical/memory-layout.md)
- [`../../docs/technical/kernel-replacement.md`](../../docs/technical/kernel-replacement.md)
- [`../../docs/technical/indirect-calls.md`](../../docs/technical/indirect-calls.md)
