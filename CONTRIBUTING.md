# Contributing to xboxrecomp

Thanks for your interest in contributing to the Xbox static recompilation toolkit. This document covers what you need to get started, where to focus your efforts, and how to submit your work.

## Development Environment Setup

You need:

- **Windows 10/11** (the runtime targets Win32 APIs directly)
- **Visual Studio 2022** with the C/C++ workload (MSVC compiler required)
- **CMake 3.20+**
- **Python 3.10+** with `capstone` installed (`pip install capstone`)
- **Git**

Build the toolkit libraries:

```bash
git clone https://github.com/sp00nznet/xboxrecomp.git
cd xboxrecomp
cmake -S . -B build
cmake --build build --config Release
```

This produces six static libraries in `build/src/*/Release/`. See the [README](README.md) for the full architecture diagram and library descriptions.

## Project Structure

The repository has two halves:

1. **Python toolchain** (`tools/`) -- parses XBE files, disassembles x86, identifies library functions, and lifts machine code to C.
2. **C runtime libraries** (`src/`) -- six static libraries that replace Xbox hardware and kernel at link time.

See the [README](README.md) for the detailed directory tree and architecture diagram.

## How to Contribute

### Pick a Game and Run the Pipeline

The most valuable contribution is trying the toolkit on a new game. Follow the Quick Start in the README, and report what works and what breaks. Even partial results (e.g., "disassembly finds 2,000 functions but the lifter chokes on SSE2 code in function X") help improve the toolkit.

To get started with a new game project, copy the template from `templates/new-game/`. Parse the exact XBE, generate a per-title target profile, validate that profile against both the parser JSON and XBE bytes, and pass the profile explicitly to disassembly, function identification, and recompilation. Never replace repository-global constants with one game's addresses and never let a command silently select a reference profile. See [Target Profiles](docs/technical/target-profiles.md) and the template files.

### Add New Kernel Exports

The verified Xbox kernel export directory uses ordinal slots through 378, with null gaps at 367–373. A title imports only the subset found in its exact XBE thunk table. Runtime support varies by ordinal and must be measured from current source and behavior rather than a stale aggregate count. To add or improve an export:

1. Find the kernel ordinal your game needs. The recompiler logs unresolved kernel calls at runtime (look for `[KERNEL] Unimplemented ordinal XXX` messages).
2. Look up the function signature on the [Xbox Dev Wiki kernel exports page](https://xboxdevwiki.net/Kernel).
3. Implement the function in the appropriate file under `src/kernel/`:
   - `kernel_memory.c` -- `MmAllocateContiguousMemory`, `MmMapIoSpace`, etc.
   - `kernel_file.c` -- `NtCreateFile`, `NtReadFile`, etc.
   - `kernel_thread.c` -- `PsCreateSystemThread`, `KeSetEvent`, etc.
   - `kernel_sync.c` -- mutexes, semaphores, critical sections
   - `kernel_rtl.c` -- RTL string and utility functions
   - `kernel_crypto.c` -- `XcSHAInit`, `XcRC4Crypt`, etc.
   - `kernel_hal.c` -- HAL functions (interrupts, DPC, timers)
   - `kernel_ob.c` -- object manager
   - `kernel_io.c` -- I/O manager
4. Register the function in `kernel_thunks.c` so the kernel bridge can dispatch to it.
5. Test by running a game that calls that ordinal.

Most kernel functions have direct Win32 equivalents. For example, `NtCreateFile` maps to `CreateFileA` with some path translation, and `KeWaitForSingleObject` maps to `WaitForSingleObject`.

### Improve the Lifter

The x86-to-C lifter lives in `tools/recomp/lifter.py`. It handles approximately 95% of x86 instructions. Areas that need work:

- **SSE/SSE2 instructions** -- many games use SIMD for math. The lifter needs patterns for `movaps`, `shufps`, `mulps`, packed operations, etc.
- **x87 FPU edge cases** -- `fprem`, `fsincos`, unusual stack manipulation patterns.
- **Segment prefix handling** -- Xbox uses `fs:` for TLS. The lifter needs to translate these to our TLS implementation.
- **Switch/jump table detection** -- indirect jumps through computed addresses (common in optimized switch statements).
- **LTCG artifacts** -- Link-Time Code Generation produces unusual calling conventions and cross-function register contracts.

When adding instruction support:
1. Add the translation pattern in `lifter.py`.
2. Preserve 100% docstring coverage for every new or modified Python module, class, function, async function, and nested function.
3. Add a focused automated test and test on a real game function that uses the instruction.
4. Verify the recompiled function produces the same behavior under the exact target profile.

### Add New Runtime Features

The runtime libraries are where most per-game work happens. Key areas:

- **D3D8 render states** (`src/d3d/`) -- Xbox D3D8 has many states not yet translated to D3D11. Each game tends to hit different subsets.
- **Audio** (`src/audio/`, `src/apu/`) -- DirectSound buffer management, 3D audio positioning, ADPCM decoding.
- **NV2A GPU** (`src/nv2a/`) -- push buffer command parsing, texture formats, vertex shader microcode.
- **Input** (`src/input/`) -- rumble/vibration, multiple controllers, keyboard/mouse for debug builds.

### Document Xbox Formats

Every Xbox game has its own asset formats. If you reverse-engineer a texture format, audio container, or level file structure, document it. Open an issue or submit a PR with your findings.

## Code Style

- **C11** standard, targeting MSVC (Visual Studio 2022).
- **No external dependencies** for the runtime libraries. Everything needed is either in the Windows SDK or self-contained in this repo.
- Use `stdint.h` types (`uint32_t`, `int16_t`, etc.) rather than platform-specific types.
- 4-space indentation, no tabs.
- Function names: `xbox_ModuleName_FunctionName` for public APIs, `snake_case` for internal helpers.
- Comments: explain *why*, not *what*. The code should be readable on its own.
- Python code must maintain 100% AST docstring coverage for every new or modified module, class, function, async function, and nested function.
- Target-bound values belong in a validated target profile or target project, not shared `config.py` modules.
- Keep files focused. Each kernel source file covers one subsystem.

## Testing

Run the automated checks that cover the changed surface, then perform target and cross-target runtime validation:

1. Run `python -m unittest tools.test_target_profile -v` for target-profile and fail-closed pipeline behavior.
2. Run `python -m compileall -q tools` and the repository's relevant focused tests.
3. Build the runtime libraries from a clean directory on each supported host configuration affected by the change.
4. Build a game project with an exact XBE, parser JSON, and validated target profile.
5. Run the recompiled game and verify the declared checkpoint rather than treating a build as runtime proof.
6. Run available reference-title regressions whenever shared code changes.

The repository does not yet provide complete automated runtime or parity coverage. Preserve that limitation and record every unavailable platform, dependency, and test surface.

The VEH crash handler and ICALL trace ring buffer are your primary debugging tools. When a game crashes, the handler prints the faulting address, all Xbox register values, and recent indirect call targets.

## Reporting Bugs and Submitting Findings

- **Bug reports**: Open a GitHub issue with the game name, the error output (crash log, ICALL failures), and the steps to reproduce.
- **Kernel gaps**: If a game needs an unimplemented kernel ordinal, file an issue with the ordinal number and which game needs it.
- **Lifter failures**: If the lifter produces incorrect C for a function, include the original disassembly and the generated C output.
- **Pull requests**: Fork the repo, make your changes on a branch, and open a PR. Describe what you changed and which game(s) you tested with.

## License

This project is licensed under the **MIT License**. By submitting a contribution, you agree that your work will be released under the same license.
