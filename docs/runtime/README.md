# Runtime implementation guide

The generated C code needs a host runtime. The shared runtime is target-neutral:
its target identity comes from a validated target profile and the exact XBE, not
from copied Burnout 3 or Xbox Dashboard constants.

## Required initialization order

1. Load the exact XBE used to create the parser analysis and target profile.
2. Call `xbox_MemoryLayoutInit()` to validate and load all XBE sections, decode
   the title thunk table, and allocate non-overlapping runtime memory.
3. Save `xbox_GetMemoryOffset()` in `g_xbox_mem_offset`.
4. Initialize the kernel implementation with `xbox_kernel_init()`.
5. Configure explicit game/save paths with `xbox_path_init()`.
6. Call `xbox_kernel_bridge_init()` and stop if it rejects the target thunk table.
7. Set `g_esp = XBOX_STACK_TOP` only after memory initialization succeeds.
8. Initialize graphics, audio, and input surfaces required by the exact title.
9. Invoke `XBOX_TARGET_ENTRY_POINT` through the generated target dispatch.

The current `templates/new-game` project generates `target_profile.h` during the
build only after the profile, parser JSON, and exact XBE agree.

## Runtime surfaces

### Memory and target layout

`src/kernel/xbox_memory_layout.c` creates the 64 MB backing store, true mirror
aliases, loads every validated XBE section, and selects safe gaps for kernel data,
the simulated stack, and the runtime heap. Do not copy section/stack/heap
addresses into a game project.

See [memory-layout.md](../technical/memory-layout.md) and
[target-profiles.md](../technical/target-profiles.md).

### Kernel replacement

The current title's XBE supplies its kernel-thunk address and populated slots.
The bridge validates and patches that table at runtime. Individual ordinal
implementations range from complete behavior to partial compatibility or
accepting stubs; report the exact surface actually tested.

See [kernel-replacement.md](../technical/kernel-replacement.md).

### Graphics

Titles can use D3D8 entry points, D3D8LTCG state, direct NV2A MMIO, and push
buffers in different combinations. Windows and POSIX builds do not currently
compile identical backends, so validate each selected host path independently.
Reference-title NV2A replay/font fixtures are opt-in and are not shared target
configuration.

See [d3d-translation.md](../technical/d3d-translation.md) and
[`../../src/nv2a/README.md`](../../src/nv2a/README.md).

### Audio

DirectSound and MCPX APU compatibility are separate layers. A successful object
creation or accepted call does not prove audible or accurate output. Validate
the active host backend, format conversion, voice state, streaming, and timing.

### Input

Map Xbox controller state to the active host input backend, including capability
queries, connected-port state, analog ranges, buttons, and vibration where
implemented. Do not infer parity from matching structure names.

## Game-specific project code

Keep these outside the shared toolkit unless a change is demonstrably reusable:

- target profile annotations and evidence,
- manual function overrides,
- asset loaders and format definitions,
- title state/context addresses,
- game-specific renderer/audio workarounds,
- parity scenarios and reference captures.

Every manual override must preserve its Xbox VA, ABI, inputs, outputs, stack
cleanup, evidence, validation, and remaining gap. Generated output remains
disposable; fix the generator or use documented manual sources rather than
editing generated files permanently.
