# Runtime Libraries

The `src/` directory contains 6 static libraries that provide the Xbox hardware and OS abstraction layer for statically recompiled games. Your recompiled game links against these at build time — no emulator needed at runtime.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Your Recompiled Game                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │ gen/recomp_*  │  │   manual     │  │  game-specific │ │
│  │ (auto-gen C)  │  │  overrides   │  │  loaders/fmt   │ │
│  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘ │
│         └─────────┬───────┘──────────────────┘           │
│                   │                                       │
│         recomp_lookup() / recomp_lookup_manual()          │
│         (dispatch table — YOU provide these)              │
├───────────────────┼───────────────────────────────────────┤
│                   │     xboxrecomp libraries              │
│         ┌─────────┴─────────┐                             │
│         │   xbox_kernel     │  Memory, files, threads,    │
│         │  (kernel_bridge)  │  sync, crypto, HAL          │
│         └─────────┬─────────┘                             │
│                   │                                       │
│  ┌────────┐ ┌─────┴───┐ ┌──────────┐ ┌───────┐ ┌──────┐│
│  │xbox_   │ │xbox_    │ │xbox_     │ │xbox_  │ │xbox_ ││
│  │d3d8    │ │dsound   │ │apu       │ │nv2a   │ │input ││
│  │        │ │         │ │          │ │       │ │      ││
│  │D3D8→   │ │DSound→  │ │MCPX APU │ │NV2A   │ │XPP→  ││
│  │D3D11   │ │mixer    │ │(xemu)   │ │(xemu) │ │XInput││
│  └────────┘ └─────────┘ └──────────┘ └───────┘ └──────┘│
├──────────────────────────────────────────────────────────┤
│    Windows: D3D11, DXGI, XInput, waveOut, Win32 API      │
└──────────────────────────────────────────────────────────┘
```

## Libraries

| Library | Dir | Origin | Description |
|---------|-----|--------|-------------|
| **xbox_kernel** | `kernel/` | Custom | Exact-XBE memory layout, validated per-title kernel-thunk dispatch, files, threads, synchronization, crypto, HAL, and other implemented/partial exports |
| **xbox_d3d8** | `d3d/` | Custom | Host-selected D3D8 compatibility backend (D3D11 on Windows, OpenGL source on POSIX) |
| **xbox_dsound** | `audio/` | Custom | DirectSound compatibility objects and mixer-facing behavior; validate audible output separately |
| **xbox_apu** | `apu/` | xemu + custom | MCPX APU state, voices, MMIO, and host audio backends |
| **xbox_nv2a** | `nv2a/` | xemu + custom | NV2A register handlers, MMIO, push-buffer processing, and host translation |
| **xbox_input** | `input/` | Custom | Xbox controller state mapped to the active host input backend |

## Building

```bash
cd xboxrecomp
cmake -S . -B build
cmake --build build --config Release
```

Output names and locations depend on the generator and host. The umbrella `xboxrecomp` CMake target links the six runtime libraries.

## Linking to Your Game

In your game's CMakeLists.txt:

```cmake
# Point to xboxrecomp
add_subdirectory(path/to/xboxrecomp)

# Link the umbrella target (all 6 libs)
target_link_libraries(my_game PRIVATE xboxrecomp)

# Or link individual modules
target_link_libraries(my_game PRIVATE xbox_kernel xbox_d3d8)
```

## Integration Contract

Your game project **must** provide two functions that the kernel bridge calls:

```c
typedef void (*recomp_func_t)(void);

// Auto-generated dispatch table (from tools/recomp output)
recomp_func_t recomp_lookup(uint32_t xbox_va);

// Hand-written function overrides
recomp_func_t recomp_lookup_manual(uint32_t xbox_va);
```

These resolve Xbox virtual addresses to native function pointers. The recompiler tool generates `recomp_dispatch.c` with a binary-search lookup table.

## Initialization Order

The current `templates/new-game` build emits `target_profile.h` only after the
profile, parser JSON, and exact XBE agree. Runtime initialization must then fail
closed when target memory or thunk validation fails:

```c
#include "kernel.h"
#include "xbox_memory_layout.h"
#include "target_profile.h"

int main(void) {
    if (!xbox_MemoryLayoutInit(xbe_data, xbe_size))
        return 1;

    g_xbox_mem_offset = xbox_GetMemoryOffset();
    xbox_kernel_init();
    xbox_path_init(game_dir, save_dir);
    if (!xbox_kernel_bridge_init())
        return 1;

    g_esp = XBOX_STACK_TOP;

    /* Initialize only the graphics, audio, NV2A, and input surfaces used by
       the selected title and host, then resolve the validated entry point. */
    recomp_func_t entry = recomp_lookup(XBOX_TARGET_ENTRY_POINT);
    if (!entry)
        return 1;
    entry();
    return 0;
}
```

The memory layer loads all target XBE sections and selects non-overlapping
kernel-data, stack, and heap ranges dynamically. The bridge uses only the
validated active thunk table for the current title.

## Per-Module Documentation

Each subdirectory has its own README with API reference:

- [kernel/README.md](kernel/README.md) — Memory layout, file I/O, threading, sync, crypto
- [d3d/README.md](d3d/README.md) — D3D8 interface, render states, textures, shaders
- [audio/README.md](audio/README.md) — DirectSound buffers, 3D audio, mixbins
- [apu/README.md](apu/README.md) — MCPX APU voice processor, mixer, MMIO
- [nv2a/README.md](nv2a/README.md) — NV2A GPU registers, push buffer, PGRAPH
- [input/README.md](input/README.md) — Gamepad state, vibration, button mapping
