# Ghidra Headless Naming Pipeline (Xbox XBE)

Recovers real function names, symbols, and decompiled C from an Xbox
XBE using **Ghidra 12.0.3 headless**, then turns them into a `{address: name}`
map the static recompiler can consume to replace `sub_XXXXXXXX` names with
meaningful ones.

The recompiler reads the explicit target `functions.json` supplied on its CLI and
emits each function as `func_info.get("name", "sub_<ADDR>")`. Put a meaningful
`name` on a validated entry and regenerated C uses it. Addresses are Xbox VAs,
so the name map, functions database, parser JSON, profile, and XBE must all refer
to the same target.

## Layout

```
tools/ghidra_naming/
  extract_for_ghidra.py          # build a flat raw image from the XBE for Ghidra
  run_ghidra.sh                  # end-to-end runner (Git Bash): extract + analyze + export
  merge_names.py                 # build ghidra_names.json (and optional --apply)
  ghidra_scripts/
    SetAnalysisOptions.java      # pre-analysis: enable FidDb/RTTI/demangler/etc.
    ExportXbeNames.py            # post-analysis: export the 3 JSONs (Jython)
    SeedFunctions.py             # optional explicit functions.json seeding

<target GHIDRA_OUT>/
  work/                          # flat image, logs, generated headless support
  project/                       # target-specific Ghidra project
  export/                        # functions.json, symbols.json, decompiled.json
  ghidra_names.json              # target-specific {address: meaningful_name}
```

## Why a flat raw image (not an XBE loader)

Ghidra 12.0.3 ships no XBE loader, and no prebuilt XBE loader extension exists
for this exact version. The reliable approach (and the one used here) is:

1. `extract_for_ghidra.py` uses the repository's `tools/xbe_parser` to read
   the exact XBE section table and assemble one flat image from the parsed base
   address through the end of the last section. Section bytes are placed at
   `(VA - base)` and gaps are zero-filled.
2. `run_ghidra.sh` reads the generated `sections.json` and imports the image as
   `x86:LE:32:default`, compiler spec `windows` (MSVC), at that exact base.
   Ghidra addresses therefore match the selected target's function starts. The
   section count and image size are target-derived; reference-title counts are
   never used as configuration.

## What does the naming

Auto-analysis runs with naming-relevant analyzers forced ON
(`SetAnalysisOptions.java`). The pre-script enables a superset and
silently skips any analyzer the current loader doesn't register:

- **Function ID** — matches code against Ghidra's bundled x86 FidDb databases
  (`vsOlder_x86`, `vs2012/2015/2017/2019_x86`, auto-discovered from the
  FunctionID module's `data/` dir). `vsOlder_x86` fits the XDK-era MSVC CRT.
  **This is the naming win on a stripped retail binary** — it recovers the
  statically linked CRT/runtime helpers (malloc, qsort, sprintf, the 64-bit
  math/`_alldiv` helpers, SEH `_global_unwind2`, `_ftol`, low-level I/O, etc.).
- **Decompiler Parameter ID / Switch Analysis**, **Scalar Operand References**,
  **Aggressive Instruction Finder**, **Shared Return Calls** — better function
  boundaries, signatures, and code coverage.

Note: **Library Identification**, **Demangler Microsoft**, and the **PE RTTI**
analyzers are PE-format–specific and are NOT registered for the *Raw Binary*
loader, so they are skipped (logged as "analyzer not present"). FidDb still
runs and is the dominant name source here. A handful of MSVC-mangled symbols
(e.g. `operator new` = `??2@YAPAXI@Z`) are still recovered via FidDb itself.

### Reference-title measured yield

The following historical measurements are from the original reference binary;
they are not expected counts for another target and must not be used as an
acceptance gate.

- Ghidra discovers ~8,360 functions from the flat image; ~6,287 land on a
  recompiler `functions.json` `start` address.
- `ghidra_names.json` = **134 meaningful (FidDb/CRT) names**, of which **131
  match recompiler function starts**. These are high-confidence library names.
- The bulk of the 22,178 recompiler functions are proprietary Criterion /
  RenderWare / D3D8LTCG game code with **no FidDb signatures**, so they keep
  their `sub_` names. 134 is effectively the FidDb ceiling for this title
  without a custom XDK/RenderWare signature database.

### Optional: function seeding (off by default)

`ghidra_scripts/SeedFunctions.py` can pre-create Ghidra functions from an
explicit target `functions.json` argument before analysis. In the historical
reference run, seeding all 22,178 candidate entry points **raised** function/address
overlap (~6,287 → ~7,370) but **slightly lowers** FidDb name matches (~131 →
~93) because seeded boundaries perturb FidDb's body hashing. Because the names
are the goal, seeding is **not** used by default. To enable, add
`-preScript SeedFunctions.py <target-functions.json>` before the
`SetAnalysisOptions` pre-script in a target-specific headless invocation.

## Run it (Git Bash)

End to end (fast: functions + symbols, no decompilation):

```bash
XBE=/path/to/default.xbe \
GHIDRA_OUT=/path/to/analysis/ghidra \
  tools/ghidra_naming/run_ghidra.sh
```

Then build the target-specific name map:

```bash
py -3 tools/ghidra_naming/merge_names.py \
  --export-dir /path/to/analysis/ghidra/export \
  --out /path/to/analysis/ghidra/ghidra_names.json
```

Optional decompilation (slow; resumable, bounded per run):

```bash
XBE=/path/to/default.xbe GHIDRA_OUT=/path/to/analysis/ghidra \
  tools/ghidra_naming/run_ghidra.sh decompile 4000
XBE=/path/to/default.xbe GHIDRA_OUT=/path/to/analysis/ghidra \
  tools/ghidra_naming/run_ghidra.sh decompile all
```

Re-run decompilation without re-analyzing (continues where it left off):

```bash
XBE=/path/to/default.xbe \
GHIDRA_OUT=/path/to/analysis/ghidra \
ANALYZE=0 IMPORT=0 \
  tools/ghidra_naming/run_ghidra.sh decompile 4000
```

### Windows-shell note

`run_ghidra.sh` invokes Ghidra's Windows `analyzeHeadless.bat` directly and
converts target paths with `cygpath` when available. Run it from Git Bash or
another Bash environment that can execute the configured Windows batch file.
The script does not generate or reuse a repository-global batch file.

## Outputs

- `$GHIDRA_OUT/export/functions.json` — every function:
  `{address, name, signature, calling_convention, param_count, is_thunk, namespace}`
- `$GHIDRA_OUT/export/symbols.json` — symbol table:
  `{address, name, type, namespace, source, primary}`
- `$GHIDRA_OUT/export/decompiled.json` — per-function decompiled C (when enabled):
  `{address, name, decompiled_c}`; `decompiled_progress.json` tracks resume state.
- the explicit `--out` file — `{ "0x00352560": "name", ... }`, **meaningful names only**.

## merge_names.py

Reads `export/functions.json` + `export/symbols.json`, filters out Ghidra
placeholders (`FUN_*`, `LAB_*`, `DAT_*`, `SUB_*`, `thunk_FUN_*`, `switchD_*`,
`caseD_*`, hex/empty), sanitizes each name to a valid C identifier, de-dupes
collisions by appending `_<addr>`, avoids C keywords, and reports counts by
source (fidb/library, demangled, rtti, symbol). It also prints how many
recovered addresses actually match the recompiler's `functions.json` `start`s.

Apply into the recompiler (writes a `.bak` first) — **left to the human/main
agent**, not run automatically:

```bash
py -3 tools/ghidra_naming/merge_names.py \
  --export-dir /path/to/analysis/ghidra/export \
  --out /path/to/analysis/ghidra/ghidra_names.json \
  --functions-json /path/to/analysis/disasm/functions.json \
  --target-profile /path/to/targets/my-game.json \
  --analysis-json /path/to/analysis/target_analysis.json \
  --xbe /path/to/default.xbe \
  --apply
```

The command validates every function range against the selected profile before
writing the database. After applying, regenerate the affected target C output.
