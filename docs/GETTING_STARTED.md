# Getting Started with Xbox Static Recompilation

This guide walks you through recompiling your first Xbox game, from extracting the XBE to getting the game running on Windows.

## What You Need

- **Windows 11** (or 10 with recent updates)
- **Python 3.10+** with `capstone` installed (`pip install capstone`)
- **Visual Studio 2022** (MSVC compiler) with C/C++ desktop workload
- **CMake 3.20+**
- An original Xbox game disc image (ISO/XISO) — you must own the game
- A tool to extract ISO files ([extract-xiso](https://github.com/XboxDev/extract-xiso) or [xdvdfs](https://github.com/antangelo/xdvdfs))

Optional but very helpful:
- **xemu** — Xbox emulator for live debugging via GDB stub
- **Ghidra/IDA** — for manual analysis of tricky functions
- **Your game's PC port source** (if leaked/available) — for understanding game logic

## Step 0: Set Up Your Project

```bash
# Clone the toolkit
git clone https://github.com/sp00nznet/xboxrecomp.git

# Create your game-specific repo
mkdir my_xbox_game
cd my_xbox_game
git init

# Build the runtime libraries
cd ../xboxrecomp
cmake -S . -B build
cmake --build build --config Release
cd ../my_xbox_game
```

## Step 1: Extract the XBE

Extract `default.xbe` and game data files from your disc image:

```bash
# Using extract-xiso
extract-xiso -x "My Game.iso" -d game_files/

# Or using xdvdfs
xdvdfs unpack "My Game.iso" game_files/
```

You should now have:
```
game_files/
├── default.xbe          # The game executable
├── Data/                # Game data (textures, models, levels)
├── Video/               # FMV files (XMV format)
└── ...                  # Other game-specific files
```

## Step 2: Parse the XBE

```bash
mkdir -p analysis targets
py -3 -m tools.xbe_parser game_files/default.xbe \
  --json analysis/target_analysis.json
```

Keep the JSON with the exact XBE. It records the decoded entry point, section
coordinates and flags, kernel imports, TLS, certificates, and library metadata.
Do not copy example addresses from another title.

## Step 3: Generate and Validate the Target Profile

```bash
py -3 -m tools.target_profile generate \
  --analysis-json analysis/target_analysis.json \
  --xbe game_files/default.xbe \
  --output targets/my-game.json

py -3 -m tools.target_profile validate \
  --profile targets/my-game.json \
  --analysis-json analysis/target_analysis.json \
  --xbe game_files/default.xbe
```

The profile contains immutable parser-derived values plus optional evidence-backed
annotations. It replaces the old practice of editing global Burnout 3 or Dashboard
address constants. Read [Target Profiles](technical/target-profiles.md) before
approving nonstandard code sections or special helper addresses.

## Step 4: Disassemble

```bash
py -3 -m tools.disasm game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/my-game.json \
  --output analysis/disasm -v
```

The output directory is explicit and target-specific. Review candidates, overlaps,
out-of-profile ranges, and uncovered executable gaps rather than treating a large
function count as proof of correctness.

## Step 5: Identify Library Functions

```bash
py -3 -m tools.func_id game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/my-game.json \
  --functions analysis/disasm/functions.json \
  --strings analysis/disasm/strings.json \
  --xrefs analysis/disasm/xrefs.json \
  --output analysis/func-id -v
```

Every function range is checked against the selected profile. RenderWare
identification runs only when explicitly enabled for a supported title.

## Step 6: Recompile and Set Up the Build

```bash
py -3 -m tools.recomp game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/my-game.json \
  --functions analysis/disasm/functions.json \
  --labels analysis/disasm/labels.json \
  --identified analysis/func-id/identified_functions.json \
  --output-dir analysis/recomp \
  --all --split 1000 --gen-dir src/recomp/gen
```

Start the project from `templates/new-game/`. Its CMake file validates the target
profile, parser JSON, and exact XBE before generating `target_profile.h`. The runtime
entry point, kernel-thunk address, and ICALL code ranges come from that generated
header; do not hand-edit them in `main.c` or `recomp_types.h`.

The memory runtime parses all sections directly from the XBE and selects a verified
free gap for kernel data, the simulated stack, and the runtime heap. It fails when
no safe layout exists instead of reusing a reference-title range.

## Step 7: Build and Crash

```bash
cmake -S . -B build
cmake --build build --config Release
bin\my_game.exe 2>stderr.txt
```

**It will crash.** That's expected and normal. The stderr log tells you what happened.

## Step 8: Debug Iteratively

This is where the real work begins. The general pattern:

1. **Run** — game crashes
2. **Read stderr** — look for ICALL failures, bad memory access, assertion failures
3. **Identify the problem** — usually one of:
   - Missing ICALL target (function pointer the dispatch table doesn't know about)
   - Bad memory access (pointer to Xbox memory that hasn't been mapped)
   - Unimplemented kernel function (game calls a function we stubbed)
   - Corrupted vtable (native pointer where Xbox VA expected)
4. **Fix it** — add a manual override, stub the function, fix the dispatch table
5. **Rebuild and repeat**

### Common First Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Crash in ICALL dispatch | Unknown function pointer | Add function to dispatch table or stub it |
| Access violation at 0xFD...... | GPU MMIO access | Initialize NV2A and MMIO hooks |
| Access violation at 0xFE...... | APU MMIO access | Initialize APU and MMIO hooks |
| "SKIP-READ" in stderr | Access to unmapped memory | Check mirror views; might be native ptr confusion |
| Infinite loop | Game waiting for hardware | Stub the wait function or fake the hardware state |
| Stack overflow | Recursive calls or wrong ESP | Check stack setup, ensure ESP starts correctly |

### The ICALL Trace

The most powerful debugging tool. When an indirect call fails, the trace shows:

```
[ICALL] unknown target 0x001A3F50 from RVA 0x000165F0
```

This tells you: function at 0x000165F0 tried to call 0x001A3F50, but it's not in the dispatch table. Usually means you need to add it to `recomp_dispatch.c` or create a manual override.

### Manual Overrides

When a recompiled function doesn't work (crashes, loops forever, reads hardware), replace it:

```c
// In recomp_manual.c
void sub_001A3F50(void) {
    // The original function reads GPU registers we haven't set up.
    // For now, just return success.
    eax = 1;
    esp += 4; return;  // Clean up fake return address
}
```

Register your override in the manual lookup table so ICALLs find it.

## Step 9: Get to Menus

The typical boot sequence for an Xbox game:

1. **CRT startup** — `_mainCRTStartup` → `main()` or `WinMain()`
2. **Hardware init** — D3D device creation, DirectSound init, input setup
3. **Asset loading** — textures, models, levels from disc
4. **Menu system** — title screen, main menu
5. **Gameplay** — the actual game

Each phase introduces new challenges. Hardware init needs working kernel + D3D stubs. Asset loading needs file I/O. Menus need rendering. Gameplay needs everything.

Focus on getting past each phase one at a time.

## Step 10: Beyond Boot

Once the game boots and shows something on screen, you're past the hardest part. From here:

- **Add missing features** — audio, input, save/load
- **Fix rendering** — texture formats, shader states, blend modes
- **Optimize** — profile, find bottlenecks, add proper shader support
- **Mod** — the generated C code is yours to modify. Add HD support, widescreen, new features.

## Tips

- **Start with a simple game** — pick something small with a known engine (RenderWare games are good targets)
- **Use xemu for reference** — run the game in xemu with GDB debugging to understand what memory addresses mean
- **Keep notes** — document every address, every function you identify, every patch you make
- **Don't try to fix everything at once** — stub what you can, fix what you must
- **The 80/20 rule applies** — 80% of functions "just work" in recompiled form. The other 20% is where you spend your time.
- **Read the technical docs** — especially [indirect-calls.md](technical/indirect-calls.md) and [lessons-learned.md](technical/lessons-learned.md)
