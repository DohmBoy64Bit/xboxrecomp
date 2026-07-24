# Target Profiles

The analysis and recompilation tools must never infer a title from repository-global
configuration. Every run is bound to the exact XBE through parser analysis and,
for durable projects, a versioned target profile.

## Why profiles exist

Earlier versions of the toolkit stored Burnout 3 section ranges in the disassembler
and function identifier, Xbox Dashboard build 3944 ranges in the recompiler, and
Burnout-specific SEH helper addresses in the lifter. Replacing one title's numbers
with another title's numbers merely moved the unsafe global default.

A target profile separates two kinds of data:

- **Immutable XBE identity**: base address, image size, entry point, kernel-thunk
  address, section virtual ranges, raw ranges, and section flags. These values come
  from parser output and can be cross-checked against the exact XBE bytes.
- **Evidence-backed annotations**: approved code roles for nonstandard sections,
  XDK/library categories, special functions such as `seh_prolog`, and optional
  title-specific identification vocabulary.

Reference profiles under `targets/` are explicit fixtures. No tool selects them
because a path is missing.

## Create a profile

First create machine-readable parser output for the exact XBE. Then generate and
bind the profile to the XBE hash and section table:

```bash
python -m tools.target_profile generate \
  --analysis-json analysis/target_analysis.json \
  --xbe game_files/default.xbe \
  --profile-id laylat-wars-retail \
  --title "Laylat Wars" \
  --output targets/laylat-wars-retail.json
```

Generation preserves the parser-derived section flags. To approve a section that
contains code despite a missing executable flag, change only its profile `role` to
`code` and record the evidence in project documentation. Do not alter its immutable
coordinates or rewrite the parser output.

## Validate before every phase

```bash
python -m tools.target_profile validate \
  --profile targets/laylat-wars-retail.json \
  --analysis-json analysis/target_analysis.json \
  --xbe game_files/default.xbe
```

Validation fails when the XBE hash, entry point, thunk address, image size, section
name, virtual range, raw range, or flags disagree. It also rejects overlapping
sections, invalid roles, special-function addresses outside approved code, and
profiles without code sections.

## Use explicit target paths

```bash
python -m tools.disasm game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/laylat-wars-retail.json \
  --output analysis/disasm

python -m tools.func_id game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/laylat-wars-retail.json \
  --functions analysis/disasm/functions.json \
  --strings analysis/disasm/strings.json \
  --xrefs analysis/disasm/xrefs.json \
  --output analysis/func-id

python -m tools.recomp game_files/default.xbe \
  --analysis-json analysis/target_analysis.json \
  --target-profile targets/laylat-wars-retail.json \
  --functions analysis/disasm/functions.json \
  --labels analysis/disasm/labels.json \
  --identified analysis/func-id/identified_functions.json \
  --output-dir analysis/recomp \
  --all --split 1000 --gen-dir src/recomp/gen
```

The function identifier and recompiler validate every function range against the
selected profile. The recompiler also rejects labels outside approved code and
classification or ABI records that do not correspond to the selected function
database. Explicit paths prevent one target from consuming another target's
repository-relative output directory.

## Generated runtime header

Game builds should generate `target_profile.h` rather than copying addresses into
`main.c` or `recomp_types.h`:

```bash
python -m tools.target_profile emit-c-header \
  --profile targets/laylat-wars-retail.json \
  --analysis-json analysis/target_analysis.json \
  --xbe game_files/default.xbe \
  --output build/generated/target_profile.h
```

The header contains the validated title identity, entry point, thunk address,
special-function constants, a code-address predicate covering every approved code
section, and `xbox_target_va_to_file_offset()` for translating file-backed target
addresses without title-specific section arithmetic. Indirect-call guards use the
predicate instead of a hand-edited `.text` range; original-XBE fallback reads use
the generated VA-to-file-offset helper and reject BSS-only or out-of-profile VAs.

## Runtime generalization

The runtime parses all section locations and the kernel-thunk table from the exact
XBE. Kernel data, the simulated stack, and the runtime heap are placed in a verified
free Xbox RAM gap that does not overlap the XBE header or any loaded section. If no
safe gap exists, initialization fails instead of reusing a reference-title address.

The shared runtime leaves target-specific `fs:[0x28]` state unset. A game project
may call `xbox_MemoryLayoutSetFs28Context()` only after identifying the correct
context address for that exact binary.

## What remains fixed

Do not move genuine platform constants into profiles. Examples include NV2A/PAPU
register offsets, Xbox RAM size and mirroring behavior, kernel ordinal identities,
and the host runtime's synthetic kernel-dispatch range. A hexadecimal constant is
not target-specific merely because it appears in code.

## Reference fixtures

`targets/burnout3-retail.json` and `targets/xbox-dashboard-3944.json` preserve the
legacy target maps for explicit regression and research use. Burnout 3 NV2A replay,
font-atlas, and captured push-buffer paths are disabled by default and require
`XBOXRECOMP_BUILD_BURNOUT3_NV2A_FIXTURES=ON`.
