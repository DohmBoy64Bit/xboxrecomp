# Recompilation Toolchain

Python tools that transform an Xbox executable (XBE) into compilable C source code. Run them in sequence — each tool's output feeds the next.

## Prerequisites

```bash
pip install capstone    # x86 disassembly engine
```

Python 3.10+ required. On Windows, use `py -3` instead of `python3`.

## Pipeline Overview

Every stage is bound to the exact target. The parser produces immutable XBE
metadata; `tools.target_profile` turns it into a validated per-title profile;
and all downstream databases and output directories are passed explicitly.

```text
default.xbe
    └─ tools.xbe_parser --json analysis/target_analysis.json
          └─ tools.target_profile generate --xbe default.xbe
                ├─ tools.disasm --output analysis/disasm
                ├─ tools.func_id --functions/--strings/--xrefs ...
                └─ tools.recomp --functions ... --gen-dir src/recomp/gen
```

Reference profiles under `targets/` are opt-in fixtures. Missing target input is
an error; no command silently selects Burnout 3 or Xbox Dashboard addresses.
See [Target Profiles](../docs/technical/target-profiles.md).

## Tool Details

### 1. xbe_parser — XBE File Parser

Reads an Xbox executable and extracts all metadata needed by downstream tools.

```bash
py -3 -m tools.xbe_parser game_files/default.xbe \
  --json analysis/target_analysis.json
```

**What it extracts:**
- Base address (always 0x00010000 for retail XBEs)
- Entry point (XOR-decoded from header)
- XDK version (build number)
- Certificate info (title name, allowed media types)
- Section table (name, VA, size, raw offset for each section)
- Kernel thunk table (ordinal imports)
- TLS directory
- Library versions (statically linked XDK libs)

**Output:** Human-readable text plus the requested machine-readable JSON. Example values below are illustrative, not reusable configuration:

```
Entry Point:   0x001D2807
XDK Version:   5849
Sections:
  .text    VA=0x00011000  Size=2863616  RawOff=0x1000
  .rdata   VA=0x0036B7C0  Size=289684   RawOff=0x2BD7C0
  .data    VA=0x003B2360  Size=3904988  RawOff=0x302360
  ...
Kernel Imports: 147 ordinals
```

Generate a target profile from the JSON and exact XBE; do not copy these example values into shared headers.

---

### 2. disasm — Disassembler & Function Detector

Performs static analysis across every code section approved by the selected target profile.

```bash
py -3 -m tools.disasm game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/my-game.json \
  --output analysis/disasm
```

**Required target inputs:**
| Flag | Description |
|------|-------------|
| `--analysis-json FILE` | Parser JSON for the exact XBE |
| `--target-profile FILE` | Optional annotations, cross-checked against JSON and XBE |
| `--output DIR` | Explicit target-specific database/output directory |
| `--text-only` | Analyze only `.text`; omit for every approved code section |
| `--extra-sections NAMES` | Additional sections already approved as code by the selected profile |
| `--seed-functions FILE` | Additional entry points with recorded provenance |
| `--verbose` / `-v` | Show progress during analysis |

**How it works:**
1. **Linear sweep** — disassembles every byte, looking for function prologues (`push ebp; mov ebp, esp` or `sub esp, N`)
2. **Recursive descent** — follows call/jump targets to discover more functions
3. **Cross-reference analysis** — builds call graph, identifies callers/callees
4. **String detection** — finds ASCII/Unicode strings referenced by code

**Output files:**
| File | Contents |
|------|----------|
| `functions.json` | Array of function ranges with `start`, `end`, size, discovery evidence, calls, and callers |
| `xrefs.json` | Cross-reference database (call graph) |
| `strings.json` | Discovered string references |
| `summary.json` | Summary statistics and analyzed-section counts |

**Validation requirement:** Report candidates, overlaps, uncovered code gaps,
and out-of-profile ranges. Function-count growth is not evidence of correctness,
and unresolved callbacks remain explicit until supported by static or runtime evidence.

---

### 3. func_id — Function Identifier

Classifies functions into categories to help you understand what you're looking at.

```bash
py -3 -m tools.func_id game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/my-game.json \
  --functions analysis/disasm/functions.json \
  --strings analysis/disasm/strings.json \
  --xrefs analysis/disasm/xrefs.json \
  --output analysis/func-id -v
```

All database paths and the output directory are required. Every function range is
validated against the selected profile. RenderWare naming runs only when the profile
explicitly enables it; it is not a universal Xbox classification pass.

**Classification strategies:**

| Strategy | What It Detects |
|----------|----------------|
| **CRT identifier** | C runtime: malloc, free, memcpy, strcpy, printf, math functions |
| **RW identifier** | RenderWare engine: RwCamera*, RpWorld*, RwTexture*, RwStream* |
| **Immediate scanner** | Functions that reference known constants (vtable addresses, magic numbers) |
| **Vtable scanner** | Virtual method tables (arrays of function pointers) |
| **Stub classifier** | Empty/trivial functions (ret, xor eax,eax; ret) |
| **Clustering** | Groups similar functions by instruction patterns |

**Output:** Annotated function database with categories:

```
0x00011000  CRT     _mainCRTStartup
0x00011240  GAME    resource_loader
0x000636D0  GAME    physics_force_apply
0x001DD910  RW      RwCameraBeginUpdate
0x0034D530  RW      renderware_main_render (79KB!)
```

**Why this matters:** Knowing which functions are CRT vs RenderWare vs game code helps you prioritize. CRT functions usually "just work" in recompiled form. RenderWare functions may need manual overrides. Game functions need the most attention.

---

### 4. recomp — x86 to C Static Recompiler

The core tool. Translates every x86 instruction in every function into equivalent C code.

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

**Important options:**
| Flag | Description |
|------|-------------|
| `--functions FILE` | Required function database for this target |
| `--labels FILE` | Optional labels from the same target |
| `--identified FILE` | Optional classification database from the same target |
| `--abi FILE` | Optional ABI database from the same target |
| `--output-dir DIR` | Required summaries/single-file output directory |
| `--all` | Recompile all accepted functions |
| `--split N` | Split output into files of N functions each |
| `--gen-dir DIR` | Required durable generated-code directory when splitting |
| `--function ADDR` | Recompile one hexadecimal function address |
| `--verbose` | Show per-function progress |

**Output files:**
| File | Contents |
|------|----------|
| `gen/recomp_0000.c` ... `recomp_NNNN.c` | Recompiled function bodies (split by --split) |
| `gen/recomp_dispatch.c` | Binary-search dispatch table (ICALL resolution) |
| `gen/recomp_funcs.h` | Forward declarations for all recompiled functions |
| `gen/recomp_stubs.c` | Stub functions for unresolvable targets |

**How it translates:**

```asm
; Original x86                    ; Generated C
push ebp                          PUSH32(esp, g_seh_ebp);
mov ebp, esp                      ebp_local = esp;
sub esp, 0x10                     esp -= 0x10;
mov eax, [ebp+8]                  eax = MEM32(ebp_local + 8);
add eax, [ebp+0xC]                eax += MEM32(ebp_local + 0xC);
mov [ebp-4], eax                  MEM32(ebp_local - 4) = eax;
mov esp, ebp                      esp = ebp_local;
pop ebp                           POP32(esp, g_seh_ebp);
ret                               esp += 4; return;
```

**What it handles:**
- All standard x86 instructions (MOV, ADD, SUB, CMP, TEST, JCC, CALL, RET, etc.)
- x87 FPU (FADD, FMUL, FSTP, etc.) via C `float`/`double`
- SSE/SSE2 (MOVSS, ADDSS, MULSS, COMISS, etc.) via C `float`
- MMX (basic operations, packed byte/word/dword)
- String operations (REP MOVSB, CMPSB, STOSB, SCASB)
- Indirect calls → RECOMP_ICALL() macro dispatch
- Switch/jump tables → C switch statements
- Stack frame simulation (PUSH/POP via simulated ESP)

**What needs manual attention:**
- **Indirect calls** — 90% resolve automatically via the dispatch table. The other 10% need investigation (corrupted vtables, function pointer arrays).
- **Self-modifying code** — not supported (Xbox games rarely use this).
- **Inline assembly** — translated mechanically, but semantics may need review.
- **Large functions** — very large functions (50KB+) may have issues with branch targets spanning too far. The recompiler handles this, but edge cases exist.

---

### 5. xmv — Xbox Media Video Demuxer

Extracts video/audio streams from Xbox XMV container files.

```bash
py -3 -m tools.xmv game_files/Video/intro.xmv
```

XMV is the Xbox's proprietary video container format used for FMV sequences, boot videos, and cutscenes. This tool splits the container into separate video and audio elementary streams that can be converted with FFmpeg or played with Media Foundation.

### 6. ghidra_naming — Optional function-name recovery (Ghidra headless)

Recovers real function names from an XBE via a headless Ghidra pass and merges
them into the recompiler's `functions.json` so the generated C uses meaningful
names instead of `sub_XXXXXXXX`. Optional and supplementary — the core pipeline
does not require Ghidra.

```bash
# 1. Analyze into an explicit target-specific Ghidra root.
XBE=/path/to/default.xbe \
GHIDRA_OUT=/path/to/analysis/ghidra \
  tools/ghidra_naming/run_ghidra.sh

# 2. Build a target-specific name map.
py -3 tools/ghidra_naming/merge_names.py \
  --export-dir /path/to/analysis/ghidra/export \
  --out /path/to/analysis/ghidra/ghidra_names.json

# 3. Optional apply: exact functions database and target identity are required.
py -3 tools/ghidra_naming/merge_names.py \
  --export-dir /path/to/analysis/ghidra/export \
  --out /path/to/analysis/ghidra/ghidra_names.json \
  --functions-json /path/to/analysis/disasm/functions.json \
  --target-profile /path/to/targets/my-game.json \
  --analysis-json /path/to/analysis/target_analysis.json \
  --xbe /path/to/default.xbe \
  --apply
```

Set `GHIDRA_HOME` if Ghidra is not at the default path. Since retail XBEs are
stripped, the realistic yield is the statically-linked CRT/XDK/library functions
(FidDb signatures); proprietary engine code keeps `sub_` names unless you add
RTTI/vtable recovery or library signatures. See `tools/ghidra_naming/README.md`.

### 7. symbols/map_names.py — Exact-build MAP recovery and XDK name porting

Resolve names only when a MAP, parser analysis, and exact XBE agree on target
identity:

```bash
py -3 tools/symbols/map_names.py resolve \
  /path/to/target.map analysis/target_analysis.json \
  --target-xbe game_files/default.xbe \
  --target-profile targets/my-game.json \
  --output analysis/symbols/map_names.json
```

Port library names from another exact build with both donor and target identities
validated. By default, matching is limited to the intersection of code sections
that both profiles categorize as XDK/library surfaces:

```bash
py -3 tools/symbols/map_names.py port \
  --donor-map /path/to/donor.map \
  --donor-xbe /path/to/donor/default.xbe \
  --donor-analysis /path/to/donor_analysis.json \
  --donor-profile /path/to/donor-profile.json \
  --target-xbe game_files/default.xbe \
  --target-analysis analysis/target_analysis.json \
  --target-profile targets/my-game.json \
  --target-functions analysis/disasm/functions.json \
  --output analysis/symbols/ported_names.json
```

The tool rejects mismatched MAP entry points, wrong-target function ranges,
unapproved section overrides, and missing exact-XBE identity. Reference-title
measurements remain historical evidence, not default configuration.

---

## After Recompilation

Once you have the generated C files:

1. **Create a game project** with CMake
2. **Link against xboxrecomp** (the runtime libraries)
3. **Add recomp_types.h** from `templates/runtime/` (or use the template as reference)
4. **Build** — MSVC compiles the generated code into a native .exe
5. **Run** — it will crash. That's normal.
6. **Debug iteratively** — see [docs/pipeline/06-debugging.md](../docs/pipeline/06-debugging.md)

The generated code is intentionally verbose and mechanical — it's not meant to be pretty, it's meant to be correct. Each function maps 1:1 to the original Xbox binary.

## Regeneration

If you regenerate the recompiled code (after fixing the recompiler or re-running with new options), you'll need to **re-apply manual patches** to the gen files. Keep a list of your patches — this is the most error-prone part of the workflow.

Recommended workflow:
1. Keep manual overrides in a separate file (`recomp_manual.c`)
2. Use `#if 0` / `#endif` to disable gen functions that have manual replacements
3. Track gen patches in a document (see CLAUDE.md in the burnout3 repo for an example)
