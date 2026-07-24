#!/usr/bin/env python3
"""Classify unresolved generated symbols using an explicit target profile."""

from __future__ import annotations

import argparse
import bisect
import json
import sys
from pathlib import Path
from typing import Any, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.target_profile import TargetProfile, TargetProfileError, load_target_profile


def _load_functions(path: Path) -> list[tuple[int, int, str]]:
    """Load and normalize the function database."""
    if not path.is_file():
        raise FileNotFoundError(f"functions database not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    functions: list[tuple[int, int, str]] = []
    for index, item in enumerate(data):
        try:
            start = int(item["start"], 16)
            end = int(item["end"], 16)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid function record at index {index}: {exc}") from exc
        functions.append((start, end, item.get("name", f"sub_{start:08X}")))
    return sorted(functions)


def _load_unresolved(path: Path) -> list[int]:
    """Load unresolved symbols written as sub_XXXXXXXX names or addresses."""
    if not path.is_file():
        raise FileNotFoundError(f"unresolved-symbol list not found: {path}")
    addresses: set[int] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        token = line.removeprefix("sub_")
        try:
            addresses.add(int(token, 16))
        except ValueError as exc:
            raise ValueError(
                f"invalid unresolved symbol at {path}:{line_number}: {line!r}"
            ) from exc
    return sorted(addresses)


def _section_function_bounds(
    profile: TargetProfile,
    functions: list[tuple[int, int, str]],
) -> dict[str, list[tuple[int, int, str]]]:
    """Group known functions by their profile-approved code section."""
    grouped: dict[str, list[tuple[int, int, str]]] = {
        section.name: [] for section in profile.code_sections
    }
    for function in functions:
        section = profile.section_for_address(function[0])
        if section and section.is_code:
            grouped.setdefault(section.name, []).append(function)
    return grouped


def _classify_address(
    address: int,
    profile: TargetProfile,
    grouped_functions: dict[str, list[tuple[int, int, str]]],
) -> dict[str, Any]:
    """Classify one unresolved address without using another title's ranges."""
    section = profile.section_for_address(address)
    base: dict[str, Any] = {"address": f"0x{address:08X}"}
    if section is None:
        return {**base, "type": "unknown", "reason": "outside target sections"}
    base["section"] = section.name
    if section.is_data:
        return {**base, "type": "data_section", "estimated_end": None}

    functions = grouped_functions.get(section.name, [])
    starts = [item[0] for item in functions]
    index = bisect.bisect_right(starts, address) - 1
    next_start = section.virtual_end
    if index + 1 < len(functions):
        next_start = functions[index + 1][0]

    if index >= 0:
        function_start, function_end, function_name = functions[index]
        if address == function_start:
            return {
                **base,
                "type": "known_function",
                "parent_func": f"0x{function_start:08X}",
                "parent_name": function_name,
                "estimated_end": f"0x{function_end:08X}",
            }
        if function_start < address < function_end:
            return {
                **base,
                "type": "mid_function",
                "parent_func": f"0x{function_start:08X}",
                "parent_name": function_name,
                "offset_into_func": address - function_start,
                "estimated_end": f"0x{function_end:08X}",
            }
        if address == function_end:
            return {
                **base,
                "type": "continuation",
                "parent_func": f"0x{function_start:08X}",
                "parent_name": function_name,
                "estimated_end": f"0x{next_start:08X}",
                "gap_size": max(0, next_start - address),
            }
        previous_end = function_end
    else:
        previous_end = section.virtual_address
        next_start = functions[0][0] if functions else section.virtual_end

    if previous_end <= address < next_start:
        return {
            **base,
            "type": "gap",
            "previous_func_end": f"0x{previous_end:08X}",
            "next_func_start": f"0x{next_start:08X}",
            "estimated_end": f"0x{next_start:08X}",
            "gap_size": next_start - address,
        }
    return {**base, "type": "unknown", "reason": "unclassified code address"}


def analyze(
    profile: TargetProfile,
    functions: list[tuple[int, int, str]],
    unresolved: list[int],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Classify every unresolved address and return records plus counts."""
    grouped = _section_function_bounds(profile, functions)
    records = [
        _classify_address(address, profile, grouped)
        for address in unresolved
    ]
    counts: dict[str, int] = {}
    for record in records:
        record_type = str(record["type"])
        counts[record_type] = counts.get(record_type, 0) + 1
    return records, counts


def _build_parser() -> argparse.ArgumentParser:
    """Create the noninteractive unresolved-symbol CLI."""
    parser = argparse.ArgumentParser(
        description="Classify unresolved generated symbols for an explicit Xbox target"
    )
    parser.add_argument("--target-profile")
    parser.add_argument("--analysis-json")
    parser.add_argument("--xbe", help="Optional XBE for profile hash/bounds validation")
    parser.add_argument(
        "--functions", required=True,
        help="Explicit function database JSON for the selected target",
    )
    parser.add_argument(
        "--unresolved", required=True,
        help="Target-specific text file containing unresolved sub_XXXXXXXX symbols",
    )
    parser.add_argument(
        "--output", required=True,
        help="Target-specific detailed JSON output",
    )
    parser.add_argument(
        "--addable-output", required=True,
        help="Target-specific filtered gap/continuation candidates JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run unresolved-symbol analysis and emit a JSON summary to stdout."""
    args = _build_parser().parse_args(argv)
    try:
        profile = load_target_profile(
            profile_path=args.target_profile,
            analysis_json=args.analysis_json,
            xbe_path=args.xbe,
        )
        functions = _load_functions(Path(args.functions))
        unresolved = _load_unresolved(Path(args.unresolved))
        records, counts = analyze(profile, functions, unresolved)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        addable = [
            record for record in records
            if record["type"] in {"gap", "continuation"}
        ]
        addable_output = Path(args.addable_output)
        addable_output.parent.mkdir(parents=True, exist_ok=True)
        addable_output.write_text(
            json.dumps(addable, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({
            "status": "ok",
            "profile_id": profile.profile_id,
            "unresolved": len(unresolved),
            "counts": counts,
            "output": str(output),
            "addable_output": str(addable_output),
        }, sort_keys=True))
        return 0
    except (TargetProfileError, FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
