"""Recover and port function names from MSVC linker MAP files.

Two explicit-target modes are supported:

``resolve``
    Resolve one MAP against the exact XBE and parser analysis from the same
    build, producing an address-to-name JSON map.

``port``
    Carry XDK library names from an exact donor MAP/XBE pair onto an exact
    target XBE by matching code bytes. The target's own function database and
    target profile remain the authority for valid function starts and section
    roles.

No Burnout, Dashboard, repository-global output, or implicit target profile is
selected by this module.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.target_profile import TargetProfile, TargetProfileError, load_target_profile


SEC_RE = re.compile(
    r"^\s*([0-9a-f]{4}):([0-9a-f]{8})\s+([0-9a-f]+)H\s+(\S+)\s+(\S+)\s*$",
    re.IGNORECASE,
)
SYM_RE = re.compile(
    r"^\s*([0-9a-f]{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{8})\s",
    re.IGNORECASE,
)
ENTRY_RE = re.compile(
    r"entry point at\s+([0-9a-f]{4}):([0-9a-f]{8})",
    re.IGNORECASE,
)
DEFAULT_SIG_LEN = 12


def _parse_address(value: Any, field_name: str) -> int:
    """Parse an address field while rejecting booleans and invalid strings."""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an address, not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"{field_name} is missing or has an unsupported type")


def load_sections(analysis_path: str | Path) -> tuple[list[tuple[str, int, int, int, int]], dict[str, Any]]:
    """Load parser sections in original XBE order plus the analysis object."""
    path = Path(analysis_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("sections"), list):
        raise ValueError(f"analysis JSON lacks a sections array: {path}")
    sections: list[tuple[str, int, int, int, int]] = []
    for index, section in enumerate(data["sections"]):
        if not isinstance(section, dict):
            raise ValueError(f"analysis section {index} must be a JSON object")
        sections.append((
            str(section["name"]),
            _parse_address(section.get("virtual_addr"), f"sections[{index}].virtual_addr"),
            _parse_address(section.get("virtual_size"), f"sections[{index}].virtual_size"),
            _parse_address(section.get("raw_addr"), f"sections[{index}].raw_addr"),
            _parse_address(section.get("raw_size"), f"sections[{index}].raw_size"),
        ))
    return sections, data


def parse_map(
    map_path: str | Path,
    sections: Sequence[tuple[str, int, int, int, int]],
) -> tuple[dict[int, str], int | None]:
    """Resolve MAP section offsets into Xbox VAs using exact XBE section order."""
    lines = Path(map_path).read_text(encoding="utf-8", errors="replace").splitlines()

    section_bases: dict[int, int] = {}
    for line in lines:
        match = SEC_RE.match(line)
        if match:
            index = int(match.group(1), 16)
            if 0 < index <= len(sections):
                section_bases.setdefault(index, sections[index - 1][1])

    symbols: dict[int, str] = {}
    for line in lines:
        match = SYM_RE.match(line)
        if not match:
            continue
        index = int(match.group(1), 16)
        offset = int(match.group(2), 16)
        if index in section_bases:
            symbols[section_bases[index] + offset] = match.group(3)

    entry_point: int | None = None
    for line in lines:
        match = ENTRY_RE.search(line)
        if match:
            index = int(match.group(1), 16)
            offset = int(match.group(2), 16)
            if index in section_bases:
                entry_point = section_bases[index] + offset
            break
    return symbols, entry_point


def check_entry(entry_point: int | None, profile: TargetProfile, label: str) -> bool:
    """Verify that a MAP entry point belongs to the exact selected XBE build."""
    if entry_point is None:
        print(
            f"ERROR: {label} MAP has no entry point; exact-build identity cannot be proven",
            file=sys.stderr,
        )
        return False
    if entry_point == profile.entry_point:
        print(
            f"{label} entry point check: MATCH (0x{entry_point:08X}) for "
            f"{profile.profile_id}"
        )
        return True
    print(
        f"ERROR: {label} MAP resolves to 0x{entry_point:08X}, but the validated "
        f"XBE/profile entry point is 0x{profile.entry_point:08X}. The MAP and XBE "
        "are different builds.",
        file=sys.stderr,
    )
    return False


def va_to_off(
    sections: Sequence[tuple[str, int, int, int, int]],
    virtual_address: int,
) -> int | None:
    """Translate a virtual address to a raw XBE offset when bytes are present."""
    for _name, section_va, virtual_size, raw_address, raw_size in sections:
        delta = virtual_address - section_va
        if 0 <= delta < virtual_size and delta < raw_size:
            return raw_address + delta
    return None


def _find_all(blob: bytes, signature: bytes, limit: int = 2) -> list[int]:
    """Return up to ``limit`` byte offsets where a signature occurs."""
    offsets: list[int] = []
    position = blob.find(signature)
    while position >= 0 and len(offsets) < limit:
        offsets.append(position)
        position = blob.find(signature, position + 1)
    return offsets


def port_names(
    donor_raw: bytes,
    donor_sections: Sequence[tuple[str, int, int, int, int]],
    donor_symbols: dict[int, str],
    target_raw: bytes,
    target_sections: Sequence[tuple[str, int, int, int, int]],
    target_starts: set[int],
    section_names: set[str],
    signature_length: int,
) -> tuple[dict[int, str], dict[str, int]]:
    """Port unambiguous donor signatures onto validated target function starts."""
    if signature_length <= 0:
        raise ValueError("signature length must be positive")
    donor_ranges = {
        name: (virtual_address, virtual_address + virtual_size)
        for name, virtual_address, virtual_size, _raw_address, _raw_size in donor_sections
        if name in section_names
    }
    target_blobs = [
        (virtual_address, target_raw[raw_address:raw_address + raw_size])
        for name, virtual_address, _virtual_size, raw_address, raw_size in target_sections
        if name in section_names
    ]

    names: dict[int, str] = {}
    stats = {"unique": 0, "ambiguous": 0, "absent": 0, "unusable": 0, "off_start": 0}
    for virtual_address, name in donor_symbols.items():
        if not any(start <= virtual_address < end for start, end in donor_ranges.values()):
            continue
        raw_offset = va_to_off(donor_sections, virtual_address)
        if raw_offset is None:
            stats["unusable"] += 1
            continue
        signature = donor_raw[raw_offset:raw_offset + signature_length]
        if len(signature) < signature_length or signature.count(0) > signature_length // 2:
            stats["unusable"] += 1
            continue

        found: list[int] = []
        for section_va, blob in target_blobs:
            found.extend(section_va + offset for offset in _find_all(blob, signature))
            if len(found) > 1:
                break
        if not found:
            stats["absent"] += 1
        elif len(found) > 1:
            stats["ambiguous"] += 1
        else:
            stats["unique"] += 1
            if found[0] in target_starts:
                names[found[0]] = name
            else:
                stats["off_start"] += 1
    return names, stats


def _load_starts(functions_json: str | Path, profile: TargetProfile) -> set[int]:
    """Load and profile-validate target function ranges before name porting."""
    path = Path(functions_json)
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("functions")
    if not isinstance(data, list):
        raise ValueError(f"functions database must contain a list: {path}")
    starts: set[int] = set()
    for index, record in enumerate(data):
        if not isinstance(record, dict):
            raise ValueError(f"function record {index} must be a JSON object")
        start = _parse_address(record.get("start"), f"function[{index}].start")
        if "end" in record:
            end = _parse_address(record["end"], f"function[{index}].end")
        elif "size" in record:
            end = start + _parse_address(record["size"], f"function[{index}].size")
        else:
            raise ValueError(f"function[{index}] has neither end nor size")
        profile.validate_code_range(start, end, f"function[{index}]")
        if start in starts:
            raise ValueError(f"duplicate function start 0x{start:08X}")
        starts.add(start)
    return starts


def _write_name_map(names: dict[int, str], output_path: str | Path) -> None:
    """Write an address-sorted name map to an explicit output path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({f"0x{address:08X}": name for address, name in sorted(names.items())}, indent=1)
        + "\n",
        encoding="utf-8",
    )


def _profile_section_names(profile: TargetProfile) -> set[str]:
    """Return profile-categorized code section names eligible for XDK porting."""
    return {section.name for section in profile.code_sections if section.category}


def _build_parser() -> argparse.ArgumentParser:
    """Build the explicit donor/target MAP-name command-line interface."""
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    resolve = subparsers.add_parser(
        "resolve", help="resolve one exact MAP/XBE build to an address-name map"
    )
    resolve.add_argument("map_file")
    resolve.add_argument("analysis_json")
    resolve.add_argument("--target-xbe", required=True)
    resolve.add_argument("--target-profile")
    resolve.add_argument("-o", "--output", required=True)

    port = subparsers.add_parser(
        "port", help="port XDK names between exact donor and target builds"
    )
    port.add_argument("--donor-map", required=True)
    port.add_argument("--donor-xbe", required=True)
    port.add_argument("--donor-analysis", required=True)
    port.add_argument("--donor-profile")
    port.add_argument("--target-xbe", required=True)
    port.add_argument("--target-analysis", required=True)
    port.add_argument("--target-profile")
    port.add_argument("--target-functions", required=True)
    port.add_argument("--sig-len", type=int, default=DEFAULT_SIG_LEN)
    port.add_argument(
        "--sections",
        help=(
            "Optional comma-separated section names. By default, use the "
            "categorized code-section intersection from both profiles."
        ),
    )
    port.add_argument("-o", "--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run exact-target MAP resolution or cross-title library-name porting."""
    args = _build_parser().parse_args(argv)
    try:
        if args.mode == "resolve":
            profile = load_target_profile(
                profile_path=args.target_profile,
                analysis_json=args.analysis_json,
                xbe_path=args.target_xbe,
            )
            sections, _analysis = load_sections(args.analysis_json)
            symbols, entry_point = parse_map(args.map_file, sections)
            if not check_entry(entry_point, profile, "target"):
                return 2
            _write_name_map(symbols, args.output)
            print(f"resolved {len(symbols)} symbols for {profile.profile_id}")
            print(f"wrote {args.output}")
            return 0

        donor_profile = load_target_profile(
            profile_path=args.donor_profile,
            analysis_json=args.donor_analysis,
            xbe_path=args.donor_xbe,
        )
        target_profile = load_target_profile(
            profile_path=args.target_profile,
            analysis_json=args.target_analysis,
            xbe_path=args.target_xbe,
        )
        donor_sections, donor_analysis = load_sections(args.donor_analysis)
        target_sections, target_analysis = load_sections(args.target_analysis)
        donor_symbols, donor_entry = parse_map(args.donor_map, donor_sections)
        if not check_entry(donor_entry, donor_profile, "donor"):
            return 2

        if args.sections:
            section_names = {name.strip() for name in args.sections.split(",") if name.strip()}
        else:
            section_names = _profile_section_names(donor_profile) & _profile_section_names(
                target_profile
            )
        if not section_names:
            raise ValueError(
                "no shared profile-categorized code sections are available; "
                "supply evidence-backed --sections explicitly"
            )
        unknown_donor = section_names - {section.name for section in donor_profile.code_sections}
        unknown_target = section_names - {section.name for section in target_profile.code_sections}
        if unknown_donor or unknown_target:
            raise ValueError(
                "requested sections are not approved code in both profiles: "
                f"donor-only/missing={sorted(unknown_donor)}, "
                f"target-only/missing={sorted(unknown_target)}"
            )

        donor_version = donor_analysis.get("xdk_version")
        target_version = target_analysis.get("xdk_version")
        print(
            f"donor profile={donor_profile.profile_id} XDK={donor_version}; "
            f"target profile={target_profile.profile_id} XDK={target_version}"
        )
        target_starts = _load_starts(args.target_functions, target_profile)
        names, stats = port_names(
            Path(args.donor_xbe).read_bytes(),
            donor_sections,
            donor_symbols,
            Path(args.target_xbe).read_bytes(),
            target_sections,
            target_starts,
            section_names,
            args.sig_len,
        )
        _write_name_map(names, args.output)
        print(f"sections: {', '.join(sorted(section_names))}")
        for key in ("unique", "ambiguous", "absent", "unusable", "off_start"):
            print(f"{key}: {stats[key]}")
        print(f"kept: {len(names)}")
        print(f"wrote {args.output}")
        return 0
    except (
        FileNotFoundError,
        json.JSONDecodeError,
        OSError,
        TargetProfileError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
