#!/usr/bin/env python3
"""Load, generate, and validate per-title Xbox recompilation profiles.

A target profile separates immutable XBE-derived addresses from optional,
evidence-backed annotations such as section categories and special helper
functions.  Tools must receive either an analysis JSON, a target profile, or
both; this module never falls back to a reference game's addresses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence


PROFILE_SCHEMA_VERSION = 1
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$")
XBE_SECTION_COUNT_OFFSET = 0x011C
XBE_SECTION_HEADERS_OFFSET = 0x0120
XBE_SECTION_HEADER_SIZE = 56
XBE_SECTION_WRITABLE = 0x00000001
XBE_SECTION_EXECUTABLE = 0x00000004

SECTION_CATEGORY_DEFAULTS = {
    "D3D": "game_render",
    "D3DX": "game_render",
    "XGRPH": "game_render",
    "DSOUND": "game_audio",
    "WMADEC": "game_audio",
    "WMADECXM": "game_audio",
    "DOLBY": "game_audio",
    "XMV": "game_video",
    "XONLINE": "game_network",
    "XNET": "game_network",
    "XPP": "game_input",
}


class TargetProfileError(ValueError):
    """Raised when target-profile data is missing, inconsistent, or unsafe."""


def _parse_int(value: Any, field_name: str) -> int:
    """Parse an integer or hexadecimal string and reject ambiguous values."""
    if isinstance(value, bool):
        raise TargetProfileError(f"{field_name} must be an integer, not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0)
        except ValueError as exc:
            raise TargetProfileError(
                f"{field_name} must be an integer or 0x-prefixed hexadecimal string; "
                f"received {value!r}"
            ) from exc
    raise TargetProfileError(
        f"{field_name} must be an integer or hexadecimal string; "
        f"received {type(value).__name__}"
    )


def _parse_bool(value: Any, field_name: str) -> bool:
    """Parse a JSON boolean without accepting truthy strings or numbers."""
    if isinstance(value, bool):
        return value
    raise TargetProfileError(
        f"{field_name} must be a JSON boolean; received {type(value).__name__}"
    )


def _sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_hex(value: int) -> str:
    """Format a 32-bit Xbox address as a stable hexadecimal string."""
    return f"0x{value:08X}"


def _read_xbe_sections(raw: bytes, base_address: int) -> list[dict[str, Any]]:
    """Parse immutable section coordinates and flags from exact XBE bytes."""
    if len(raw) < XBE_SECTION_HEADERS_OFFSET + 4:
        raise TargetProfileError("XBE is truncated before the section table fields")
    count = struct.unpack_from("<I", raw, XBE_SECTION_COUNT_OFFSET)[0]
    headers_va = struct.unpack_from("<I", raw, XBE_SECTION_HEADERS_OFFSET)[0]
    if count == 0 or count > 64 or headers_va < base_address:
        raise TargetProfileError("XBE contains an invalid section table")
    headers_offset = headers_va - base_address
    if headers_offset + count * XBE_SECTION_HEADER_SIZE > len(raw):
        raise TargetProfileError("XBE section headers exceed the file size")

    sections: list[dict[str, Any]] = []
    for index in range(count):
        offset = headers_offset + index * XBE_SECTION_HEADER_SIZE
        flags, virtual_address, virtual_size, raw_address, raw_size, name_va = (
            struct.unpack_from("<IIIIII", raw, offset)
        )
        if name_va < base_address:
            raise TargetProfileError(f"XBE section {index} has an invalid name address")
        name_offset = name_va - base_address
        if name_offset >= len(raw):
            raise TargetProfileError(f"XBE section {index} name exceeds the file size")
        name_end = raw.find(b"\0", name_offset, min(len(raw), name_offset + 256))
        if name_end < 0:
            raise TargetProfileError(f"XBE section {index} name is not terminated")
        name = raw[name_offset:name_end].decode("ascii", errors="strict")
        sections.append({
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_address": raw_address,
            "raw_size": raw_size,
            "executable": bool(flags & XBE_SECTION_EXECUTABLE),
            "writable": bool(flags & XBE_SECTION_WRITABLE),
        })
    return sections


def _infer_section_role(name: str, executable: bool, writable: bool) -> str:
    """Infer a conservative section role from XBE flags and common names."""
    if executable:
        return "code"
    if name.lower() in {".rdata", "rdata"} or not writable:
        return "read-only-data"
    return "data"


@dataclass(frozen=True)
class SectionProfile:
    """Describe one XBE section and its optional analysis annotations."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    executable: bool
    writable: bool
    role: str
    category: str | None = None

    @property
    def virtual_end(self) -> int:
        """Return the exclusive virtual end address."""
        return self.virtual_address + self.virtual_size

    @property
    def is_code(self) -> bool:
        """Return whether the section is approved as code for this target."""
        return self.executable or self.role == "code"

    @property
    def is_data(self) -> bool:
        """Return whether the section is approved as data for this target."""
        return not self.is_code

    def contains_virtual_address(self, address: int) -> bool:
        """Return whether an Xbox virtual address lies in this section."""
        return self.virtual_address <= address < self.virtual_end

    def virtual_to_file_offset(self, address: int) -> int | None:
        """Translate a section-contained virtual address to an XBE file offset."""
        if not self.contains_virtual_address(address):
            return None
        delta = address - self.virtual_address
        if delta >= self.raw_size:
            return None
        return self.raw_address + delta

    def to_dict(self) -> dict[str, Any]:
        """Serialize the section using stable field names and hexadecimal addresses."""
        result: dict[str, Any] = {
            "name": self.name,
            "virtual_address": _format_hex(self.virtual_address),
            "virtual_size": self.virtual_size,
            "raw_address": _format_hex(self.raw_address),
            "raw_size": self.raw_size,
            "executable": self.executable,
            "writable": self.writable,
            "role": self.role,
        }
        if self.category:
            result["category"] = self.category
        return result


@dataclass(frozen=True)
class TargetProfile:
    """Hold all target-bound values consumed by analysis and lifting tools."""

    profile_id: str
    title: str
    base_address: int
    image_size: int
    entry_point: int
    kernel_thunk_address: int
    sections: tuple[SectionProfile, ...]
    special_functions: Mapping[str, int]
    renderware_identification: bool = False
    game_subcategories: Mapping[str, tuple[str, ...]] | None = None
    xbe_sha256: str | None = None
    source: Mapping[str, Any] | None = None

    @property
    def code_sections(self) -> tuple[SectionProfile, ...]:
        """Return sections approved as code in virtual-address order."""
        return tuple(section for section in self.sections if section.is_code)

    @property
    def data_sections(self) -> tuple[SectionProfile, ...]:
        """Return sections approved as data in virtual-address order."""
        return tuple(section for section in self.sections if section.is_data)

    @property
    def primary_code_section(self) -> SectionProfile:
        """Return .text when present, otherwise the first approved code section."""
        for section in self.code_sections:
            if section.name == ".text":
                return section
        if not self.code_sections:
            raise TargetProfileError(
                f"target profile {self.profile_id!r} has no approved code sections"
            )
        return self.code_sections[0]

    @property
    def primary_read_only_section(self) -> SectionProfile | None:
        """Return .rdata or the first non-writable data section when available."""
        for section in self.data_sections:
            if section.name == ".rdata":
                return section
        for section in self.data_sections:
            if not section.writable:
                return section
        return None

    @property
    def xdk_sections(self) -> Mapping[str, tuple[int, int, str]]:
        """Return categorized library-section ranges for function clustering."""
        return {
            section.name: (
                section.virtual_address,
                section.virtual_end,
                section.category,
            )
            for section in self.code_sections
            if section.category
        }

    def section_for_address(self, address: int) -> SectionProfile | None:
        """Return the section containing an Xbox virtual address, if any."""
        for section in self.sections:
            if section.contains_virtual_address(address):
                return section
        return None

    def is_code_address(self, address: int) -> bool:
        """Return whether an address belongs to an approved code section."""
        section = self.section_for_address(address)
        return bool(section and section.is_code)

    def is_data_address(self, address: int) -> bool:
        """Return whether an address belongs to an approved data section."""
        section = self.section_for_address(address)
        return bool(section and section.is_data)

    def validate_code_range(self, start: int, end: int, label: str = "range") -> None:
        """Reject a function range that is invalid or crosses a code boundary."""
        if end <= start:
            raise TargetProfileError(
                f"{label} has an invalid range: {_format_hex(start)}-"
                f"{_format_hex(end)}"
            )
        section = self.section_for_address(start)
        if section is None or not section.is_code:
            raise TargetProfileError(
                f"{label} starts outside approved code sections: {_format_hex(start)}"
            )
        if end > section.virtual_end:
            raise TargetProfileError(
                f"{label} crosses the {section.name} section boundary: "
                f"{_format_hex(start)}-{_format_hex(end)} exceeds "
                f"{_format_hex(section.virtual_end)}"
            )

    def virtual_to_file_offset(self, address: int) -> int | None:
        """Translate an Xbox virtual address to an XBE file offset."""
        for section in self.sections:
            offset = section.virtual_to_file_offset(address)
            if offset is not None:
                return offset
        return None

    def special_function(self, name: str) -> int | None:
        """Return an evidence-backed special-function address by symbolic key."""
        return self.special_functions.get(name)

    def validate_xbe(self, xbe_path: Path) -> None:
        """Cross-check immutable profile fields against an exact XBE file."""
        if not xbe_path.is_file():
            raise TargetProfileError(f"XBE file not found: {xbe_path}")
        raw = xbe_path.read_bytes()
        if len(raw) < 0x15C or raw[:4] != b"XBEH":
            raise TargetProfileError(f"invalid or truncated XBE file: {xbe_path}")

        base_address = struct.unpack_from("<I", raw, 0x0104)[0]
        image_size = struct.unpack_from("<I", raw, 0x010C)[0]
        entry_raw = struct.unpack_from("<I", raw, 0x0128)[0]
        thunk_raw = struct.unpack_from("<I", raw, 0x0158)[0]
        candidates = (
            (entry_raw ^ 0xA8FC57AB, thunk_raw ^ 0x5B6D40B6, "retail"),
            (entry_raw ^ 0x94859D4B, thunk_raw ^ 0xEFB1F152, "debug"),
        )
        decoded = next(
            (
                (entry, thunk, kind)
                for entry, thunk, kind in candidates
                if base_address <= entry < base_address + image_size
            ),
            None,
        )
        if decoded is None:
            raise TargetProfileError("XBE entry-point encoding is neither valid retail nor debug")
        entry_point, kernel_thunk_address, _kind = decoded

        exact_fields = {
            "base_address": (self.base_address, base_address),
            "image_size": (self.image_size, image_size),
            "entry_point": (self.entry_point, entry_point),
            "kernel_thunk_address": (
                self.kernel_thunk_address,
                kernel_thunk_address,
            ),
        }
        for field_name, (expected, actual) in exact_fields.items():
            if expected != actual:
                raise TargetProfileError(
                    f"profile/XBE mismatch for {field_name}: profile "
                    f"{_format_hex(expected) if field_name != 'image_size' else expected}, "
                    f"XBE {_format_hex(actual) if field_name != 'image_size' else actual}"
                )

        exact_sections = _read_xbe_sections(raw, base_address)
        if len(exact_sections) != len(self.sections):
            raise TargetProfileError(
                f"profile/XBE section-count mismatch: profile {len(self.sections)}, "
                f"XBE {len(exact_sections)}"
            )
        exact_by_name = {section["name"]: section for section in exact_sections}
        if len(exact_by_name) != len(exact_sections):
            raise TargetProfileError("XBE contains duplicate section names")
        immutable_section_fields = (
            "virtual_address", "virtual_size", "raw_address",
            "raw_size", "executable", "writable",
        )
        for profile_section in self.sections:
            exact_section = exact_by_name.get(profile_section.name)
            if exact_section is None:
                raise TargetProfileError(
                    f"profile section {profile_section.name!r} is absent from the XBE"
                )
            profile_values = {
                "virtual_address": profile_section.virtual_address,
                "virtual_size": profile_section.virtual_size,
                "raw_address": profile_section.raw_address,
                "raw_size": profile_section.raw_size,
                "executable": profile_section.executable,
                "writable": profile_section.writable,
            }
            for field_name in immutable_section_fields:
                if profile_values[field_name] != exact_section[field_name]:
                    raise TargetProfileError(
                        f"profile/XBE section mismatch for {profile_section.name!r} "
                        f"field {field_name}: profile {profile_values[field_name]!r}, "
                        f"XBE {exact_section[field_name]!r}"
                    )

        file_size = len(raw)
        for section in self.sections:
            if section.raw_address + section.raw_size > file_size:
                raise TargetProfileError(
                    f"section {section.name!r} exceeds XBE size: raw range "
                    f"0x{section.raw_address:X}-0x{section.raw_address + section.raw_size:X}, "
                    f"file size 0x{file_size:X}"
                )
        if self.xbe_sha256:
            actual_hash = hashlib.sha256(raw).hexdigest()
            if actual_hash.lower() != self.xbe_sha256.lower():
                raise TargetProfileError(
                    f"XBE SHA-256 mismatch for profile {self.profile_id!r}: "
                    f"expected {self.xbe_sha256.lower()}, got {actual_hash.lower()}"
                )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete target profile to JSON-compatible data."""
        result: dict[str, Any] = {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "profile_id": self.profile_id,
            "title": self.title,
            "base_address": _format_hex(self.base_address),
            "image_size": self.image_size,
            "entry_point": _format_hex(self.entry_point),
            "kernel_thunk_address": _format_hex(self.kernel_thunk_address),
            "sections": [section.to_dict() for section in self.sections],
            "special_functions": {
                key: _format_hex(value)
                for key, value in sorted(self.special_functions.items())
            },
            "features": {
                "renderware_identification": self.renderware_identification
            },
            "classification": {
                "game_subcategories": {
                    key: list(values)
                    for key, values in sorted((self.game_subcategories or {}).items())
                }
            },
        }
        if self.xbe_sha256:
            result["xbe_sha256"] = self.xbe_sha256.lower()
        if self.source:
            result["source"] = dict(self.source)
        return result


def _parse_section(section: Mapping[str, Any], prefix: str) -> SectionProfile:
    """Parse one complete section record from profile or analysis data."""
    name = str(section.get("name", "")).strip()
    if not name:
        raise TargetProfileError(f"{prefix}.name must be non-empty")
    virtual_address = _parse_int(
        section.get("virtual_address", section.get("virtual_addr")),
        f"{prefix}.virtual_address",
    )
    virtual_size = _parse_int(section.get("virtual_size"), f"{prefix}.virtual_size")
    raw_address = _parse_int(
        section.get("raw_address", section.get("raw_addr")),
        f"{prefix}.raw_address",
    )
    raw_size = _parse_int(section.get("raw_size"), f"{prefix}.raw_size")
    if virtual_size <= 0:
        raise TargetProfileError(f"{prefix}.virtual_size must be positive")
    if raw_address < 0 or raw_size < 0 or virtual_address < 0:
        raise TargetProfileError(f"{prefix} addresses and sizes must be non-negative")
    executable = _parse_bool(section.get("executable", False), f"{prefix}.executable")
    writable = _parse_bool(section.get("writable", False), f"{prefix}.writable")
    role = str(
        section.get("role")
        or _infer_section_role(name, executable=executable, writable=writable)
    )
    if role not in {"code", "data", "read-only-data", "resource"}:
        raise TargetProfileError(
            f"{prefix}.role must be one of code, data, read-only-data, resource"
        )
    category_value = section.get("category")
    category = str(category_value) if category_value else SECTION_CATEGORY_DEFAULTS.get(name)
    return SectionProfile(
        name=name,
        virtual_address=virtual_address,
        virtual_size=virtual_size,
        raw_address=raw_address,
        raw_size=raw_size,
        executable=executable,
        writable=writable,
        role=role,
        category=category,
    )


def _validate_profile_identity(profile_id: str, title: str) -> None:
    """Validate human and machine-readable target identity fields."""
    if not PROFILE_ID_RE.fullmatch(profile_id):
        raise TargetProfileError(
            "profile_id must contain lowercase letters, numbers, and hyphens "
            "without leading or trailing hyphens"
        )
    if not title.strip():
        raise TargetProfileError("title must be non-empty")


def _validate_section_layout(sections: Sequence[SectionProfile]) -> None:
    """Reject duplicate names, virtual overlaps, and missing code sections."""
    if not sections:
        raise TargetProfileError("target profile must contain at least one section")
    names: set[str] = set()
    ordered = sorted(sections, key=lambda item: item.virtual_address)
    for section in ordered:
        if section.name in names:
            raise TargetProfileError(f"duplicate section name: {section.name!r}")
        names.add(section.name)
    for left, right in zip(ordered, ordered[1:]):
        if left.virtual_end > right.virtual_address:
            raise TargetProfileError(
                f"virtual sections overlap: {left.name!r} ends at "
                f"{_format_hex(left.virtual_end)}, {right.name!r} starts at "
                f"{_format_hex(right.virtual_address)}"
            )
    if not any(section.is_code for section in sections):
        raise TargetProfileError("target profile has no approved code sections")


def _parse_special_functions(data: Mapping[str, Any]) -> dict[str, int]:
    """Parse optional evidence-backed helper addresses from a profile."""
    result: dict[str, int] = {}
    for name, value in data.items():
        if value is None:
            continue
        if not isinstance(name, str) or not name.strip():
            raise TargetProfileError("special-function keys must be non-empty strings")
        result[name] = _parse_int(value, f"special_functions.{name}")
    return result




def _parse_game_subcategories(data: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Parse optional per-target game-classification keyword groups."""
    result: dict[str, tuple[str, ...]] = {}
    for category, values in data.items():
        if not isinstance(category, str) or not category.strip():
            raise TargetProfileError("game-subcategory names must be non-empty strings")
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise TargetProfileError(
                f"classification.game_subcategories.{category} must be an array of strings"
            )
        result[category] = tuple(item.lower() for item in values if item.strip())
    return result

def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    """Read a JSON object with a context-rich error message."""
    if not path.is_file():
        raise TargetProfileError(f"{label} not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TargetProfileError(f"failed to read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TargetProfileError(f"{label} must contain a JSON object: {path}")
    return value


def profile_from_analysis(
    analysis: Mapping[str, Any],
    *,
    profile_id: str | None = None,
    title: str | None = None,
    source: Mapping[str, Any] | None = None,
) -> TargetProfile:
    """Create a complete target profile from XBE parser analysis output."""
    resolved_title = str(title or analysis.get("title") or "Unknown Xbox title")
    resolved_id = profile_id or _slugify(resolved_title)
    _validate_profile_identity(resolved_id, resolved_title)
    raw_sections = analysis.get("sections")
    if not isinstance(raw_sections, list):
        raise TargetProfileError("analysis JSON must contain a sections array")
    sections = tuple(
        _parse_section(section, f"analysis.sections[{index}]")
        for index, section in enumerate(raw_sections)
        if isinstance(section, Mapping)
    )
    if len(sections) != len(raw_sections):
        raise TargetProfileError("every analysis section must be a JSON object")
    _validate_section_layout(sections)
    profile = TargetProfile(
        profile_id=resolved_id,
        title=resolved_title,
        base_address=_parse_int(analysis.get("base_address"), "analysis.base_address"),
        image_size=_parse_int(analysis.get("image_size"), "analysis.image_size"),
        entry_point=_parse_int(analysis.get("entry_point"), "analysis.entry_point"),
        kernel_thunk_address=_parse_int(
            analysis.get("kernel_thunk_addr"), "analysis.kernel_thunk_addr"
        ),
        sections=tuple(sorted(sections, key=lambda item: item.virtual_address)),
        special_functions={},
        renderware_identification=False,
        game_subcategories={},
        source=source,
    )
    _validate_core_addresses(profile)
    return profile


def _slugify(text: str) -> str:
    """Create a conservative profile identifier from a title."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "xbox-target"


def _validate_core_addresses(profile: TargetProfile) -> None:
    """Ensure target coordinates form one internally consistent XBE image."""
    if profile.base_address < 0 or profile.base_address > 0xFFFFFFFF:
        raise TargetProfileError("base_address must be a 32-bit unsigned value")
    if profile.image_size <= 0:
        raise TargetProfileError("image_size must be positive")
    image_end = profile.base_address + profile.image_size
    if image_end > 0x100000000:
        raise TargetProfileError("base_address + image_size exceeds 32-bit address space")
    highest_section_end = max(section.virtual_end for section in profile.sections)
    if highest_section_end > image_end:
        raise TargetProfileError(
            f"section layout ends at {_format_hex(highest_section_end)}, beyond image end "
            f"{_format_hex(image_end)}"
        )
    if not profile.is_code_address(profile.entry_point):
        raise TargetProfileError(
            f"entry point {_format_hex(profile.entry_point)} is not in an approved code section"
        )
    if profile.kernel_thunk_address & 3:
        raise TargetProfileError("kernel_thunk_address must be 4-byte aligned")
    thunk_section = profile.section_for_address(profile.kernel_thunk_address)
    if not thunk_section:
        raise TargetProfileError(
            f"kernel thunk address {_format_hex(profile.kernel_thunk_address)} "
            "is outside every section"
        )


def _profile_from_complete_json(data: Mapping[str, Any]) -> TargetProfile:
    """Parse a complete standalone target-profile JSON object."""
    schema_version = _parse_int(data.get("schema_version"), "schema_version")
    if schema_version != PROFILE_SCHEMA_VERSION:
        raise TargetProfileError(
            f"unsupported target-profile schema_version {schema_version}; "
            f"expected {PROFILE_SCHEMA_VERSION}"
        )
    profile_id = str(data.get("profile_id", ""))
    title = str(data.get("title", ""))
    _validate_profile_identity(profile_id, title)
    raw_sections = data.get("sections")
    if not isinstance(raw_sections, list):
        raise TargetProfileError("sections must be a JSON array")
    sections = tuple(
        _parse_section(section, f"sections[{index}]")
        for index, section in enumerate(raw_sections)
        if isinstance(section, Mapping)
    )
    if len(sections) != len(raw_sections):
        raise TargetProfileError("every section must be a JSON object")
    _validate_section_layout(sections)
    special_raw = data.get("special_functions", {})
    if not isinstance(special_raw, Mapping):
        raise TargetProfileError("special_functions must be a JSON object")
    xbe_sha256_value = data.get("xbe_sha256")
    xbe_sha256 = str(xbe_sha256_value).lower() if xbe_sha256_value else None
    if xbe_sha256 and not re.fullmatch(r"[0-9a-f]{64}", xbe_sha256):
        raise TargetProfileError("xbe_sha256 must contain exactly 64 hexadecimal characters")
    source_value = data.get("source")
    if source_value is not None and not isinstance(source_value, Mapping):
        raise TargetProfileError("source must be a JSON object when present")
    source = source_value
    features_value = data.get("features", {})
    if not isinstance(features_value, Mapping):
        raise TargetProfileError("features must be a JSON object")
    renderware_identification = _parse_bool(
        features_value.get("renderware_identification", False),
        "features.renderware_identification",
    )
    classification_value = data.get("classification", {})
    if not isinstance(classification_value, Mapping):
        raise TargetProfileError("classification must be a JSON object")
    subcategories_value = classification_value.get("game_subcategories", {})
    if not isinstance(subcategories_value, Mapping):
        raise TargetProfileError(
            "classification.game_subcategories must be a JSON object"
        )
    game_subcategories = _parse_game_subcategories(subcategories_value)
    profile = TargetProfile(
        profile_id=profile_id,
        title=title,
        base_address=_parse_int(data.get("base_address"), "base_address"),
        image_size=_parse_int(data.get("image_size"), "image_size"),
        entry_point=_parse_int(data.get("entry_point"), "entry_point"),
        kernel_thunk_address=_parse_int(
            data.get("kernel_thunk_address"), "kernel_thunk_address"
        ),
        sections=tuple(sorted(sections, key=lambda item: item.virtual_address)),
        special_functions=_parse_special_functions(special_raw),
        renderware_identification=renderware_identification,
        game_subcategories=game_subcategories,
        xbe_sha256=xbe_sha256,
        source=source,
    )
    _validate_core_addresses(profile)
    for name, address in profile.special_functions.items():
        if not profile.is_code_address(address):
            raise TargetProfileError(
                f"special function {name!r} at {_format_hex(address)} is not in code"
            )
    return profile


def _merge_analysis_and_profile(
    analysis_profile: TargetProfile,
    profile_data: Mapping[str, Any],
) -> TargetProfile:
    """Cross-check immutable values and apply only explicit profile annotations."""
    profile = _profile_from_complete_json(profile_data)
    immutable_fields = (
        "base_address",
        "image_size",
        "entry_point",
        "kernel_thunk_address",
    )
    for field_name in immutable_fields:
        expected = getattr(profile, field_name)
        actual = getattr(analysis_profile, field_name)
        if expected != actual:
            raise TargetProfileError(
                f"profile/analysis mismatch for {field_name}: profile "
                f"{_format_hex(expected) if 'address' in field_name or field_name == 'entry_point' else expected}, "
                f"analysis {_format_hex(actual) if 'address' in field_name or field_name == 'entry_point' else actual}"
            )
    analysis_by_name = {section.name: section for section in analysis_profile.sections}
    merged_sections: list[SectionProfile] = []
    for profile_section in profile.sections:
        analysis_section = analysis_by_name.get(profile_section.name)
        if analysis_section is None:
            raise TargetProfileError(
                f"profile section {profile_section.name!r} is absent from analysis JSON"
            )
        coordinates = (
            "virtual_address",
            "virtual_size",
            "raw_address",
            "raw_size",
        )
        for field_name in coordinates:
            if getattr(profile_section, field_name) != getattr(analysis_section, field_name):
                raise TargetProfileError(
                    f"profile/analysis mismatch for section {profile_section.name!r} "
                    f"field {field_name}"
                )
        if profile_section.executable != analysis_section.executable:
            raise TargetProfileError(
                f"profile may not rewrite the XBE executable flag for section "
                f"{profile_section.name!r}; use role='code' to approve nonstandard code"
            )
        if profile_section.writable != analysis_section.writable:
            raise TargetProfileError(
                f"profile/analysis mismatch for section {profile_section.name!r} writable flag"
            )
        merged_sections.append(
            replace(
                analysis_section,
                role=profile_section.role,
                category=profile_section.category,
            )
        )
    missing = sorted(set(analysis_by_name) - {section.name for section in profile.sections})
    if missing:
        raise TargetProfileError(
            "profile omits sections present in analysis JSON: " + ", ".join(missing)
        )
    merged = replace(
        analysis_profile,
        profile_id=profile.profile_id,
        title=profile.title,
        sections=tuple(sorted(merged_sections, key=lambda item: item.virtual_address)),
        special_functions=profile.special_functions,
        renderware_identification=profile.renderware_identification,
        game_subcategories=profile.game_subcategories,
        xbe_sha256=profile.xbe_sha256,
        source=profile.source,
    )
    _validate_core_addresses(merged)
    return merged


def load_target_profile(
    *,
    profile_path: str | Path | None = None,
    analysis_json: str | Path | None = None,
    xbe_path: str | Path | None = None,
) -> TargetProfile:
    """Load a target profile and fail closed when target identity is ambiguous."""
    if profile_path is None and analysis_json is None:
        raise TargetProfileError(
            "a target profile or XBE analysis JSON is required; refusing to use "
            "legacy Burnout 3 or Xbox Dashboard addresses"
        )
    profile_data: dict[str, Any] | None = None
    if profile_path is not None:
        profile_data = _load_json_object(Path(profile_path), "target profile")
    if analysis_json is not None:
        analysis_path = Path(analysis_json)
        analysis_data = _load_json_object(analysis_path, "analysis JSON")
        analysis_profile = profile_from_analysis(
            analysis_data,
            source={
                "analysis_json": str(analysis_path),
                "analysis_json_sha256": _sha256_file(analysis_path),
            },
        )
        profile = (
            _merge_analysis_and_profile(analysis_profile, profile_data)
            if profile_data is not None
            else analysis_profile
        )
    else:
        assert profile_data is not None
        profile = _profile_from_complete_json(profile_data)
    if xbe_path is not None:
        profile.validate_xbe(Path(xbe_path))
    return profile


def write_target_profile(profile: TargetProfile, output_path: str | Path) -> Path:
    """Write a target profile atomically as deterministic UTF-8 JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(profile.to_dict(), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return path


def _c_macro_component(value: str) -> str:
    """Convert a profile key into a stable uppercase C macro component."""
    component = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return component or "VALUE"


def render_c_header(profile: TargetProfile) -> str:
    """Render immutable target identity as a generated C header."""
    guard = f"XBOX_TARGET_{_c_macro_component(profile.profile_id)}_H"
    code_checks = [
        (
            f"(((uint32_t)(address)) >= {_format_hex(section.virtual_address)}u && "
            f"((uint32_t)(address)) < {_format_hex(section.virtual_end)}u)"
        )
        for section in profile.code_sections
    ]
    code_expression = " || ".join(code_checks)
    lines = [
        "/* Generated by python -m tools.target_profile emit-c-header. */",
        "/* Do not edit; regenerate from the validated target profile. */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"#define XBOX_TARGET_PROFILE_ID {json.dumps(profile.profile_id)}",
        f"#define XBOX_TARGET_TITLE {json.dumps(profile.title)}",
        f"#define XBOX_TARGET_BASE_ADDRESS {_format_hex(profile.base_address)}u",
        f"#define XBOX_TARGET_IMAGE_SIZE {profile.image_size}u",
        f"#define XBOX_TARGET_ENTRY_POINT {_format_hex(profile.entry_point)}u",
        f"#define XBOX_TARGET_KERNEL_THUNK_ADDRESS "
        f"{_format_hex(profile.kernel_thunk_address)}u",
        f"#define XBOX_TARGET_IS_CODE_ADDRESS(address) ({code_expression})",
        "",
        "static inline int xbox_target_va_to_file_offset(",
        "    uint32_t address, uint32_t *file_offset)",
        "{",
        "    if (file_offset == NULL) return 0;",
    ]
    for section in profile.sections:
        file_backed_size = min(section.virtual_size, section.raw_size)
        if file_backed_size <= 0:
            continue
        lines.extend(
            [
                f"    if (address >= {_format_hex(section.virtual_address)}u &&",
                f"        address < {_format_hex(section.virtual_address + file_backed_size)}u) {{",
                f"        *file_offset = {_format_hex(section.raw_address)}u +",
                f"            (address - {_format_hex(section.virtual_address)}u);",
                "        return 1;",
                "    }",
            ]
        )
    lines.extend(["    return 0;", "}"])
    for name, address in sorted(profile.special_functions.items()):
        lines.append(
            f"#define XBOX_TARGET_SPECIAL_{_c_macro_component(name)} "
            f"{_format_hex(address)}u"
        )
    lines.extend(["", f"#endif /* {guard} */", ""])
    return "\n".join(lines)


def write_c_header(profile: TargetProfile, output_path: str | Path) -> Path:
    """Write a generated target C header atomically."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(render_c_header(profile), encoding="utf-8")
    temporary.replace(path)
    return path


def _build_parser() -> argparse.ArgumentParser:
    """Build the noninteractive target-profile command-line interface."""
    parser = argparse.ArgumentParser(
        prog="tools.target_profile",
        description=(
            "Generate or validate per-title Xbox recompilation profiles. "
            "No reference-game profile is selected implicitly."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser(
        "generate",
        help="Generate a complete profile from XBE parser analysis JSON",
    )
    generate.add_argument("--analysis-json", required=True)
    generate.add_argument("--output", required=True)
    generate.add_argument("--profile-id")
    generate.add_argument("--title")
    generate.add_argument("--xbe", help="Optional exact XBE used for bounds validation")

    validate = subparsers.add_parser(
        "validate",
        help="Validate a profile, optionally cross-checking analysis JSON and XBE bytes",
    )
    validate.add_argument("--profile")
    validate.add_argument("--analysis-json")
    validate.add_argument("--xbe")

    emit_header = subparsers.add_parser(
        "emit-c-header",
        help="Generate a C header from a validated target profile",
    )
    emit_header.add_argument("--profile")
    emit_header.add_argument("--analysis-json")
    emit_header.add_argument("--xbe")
    emit_header.add_argument("--output", required=True)
    return parser


def _run_generate(args: argparse.Namespace) -> int:
    """Execute the profile-generation subcommand."""
    analysis_path = Path(args.analysis_json)
    analysis = _load_json_object(analysis_path, "analysis JSON")
    profile = profile_from_analysis(
        analysis,
        profile_id=args.profile_id,
        title=args.title,
        source={
            "analysis_json": str(analysis_path),
            "analysis_json_sha256": _sha256_file(analysis_path),
        },
    )
    if args.xbe:
        xbe_path = Path(args.xbe)
        profile.validate_xbe(xbe_path)
        profile = replace(
            profile,
            xbe_sha256=_sha256_file(xbe_path),
            source={
                **dict(profile.source or {}),
                "xbe": str(xbe_path),
                "xbe_sha256": _sha256_file(xbe_path),
            },
        )
    output = write_target_profile(profile, args.output)
    print(
        json.dumps(
            {
                "status": "ok",
                "profile": str(output),
                "profile_id": profile.profile_id,
                "sections": len(profile.sections),
                "code_sections": len(profile.code_sections),
                "special_functions": len(profile.special_functions),
            },
            sort_keys=True,
        )
    )
    return 0


def _run_emit_c_header(args: argparse.Namespace) -> int:
    """Execute the generated C-header subcommand."""
    profile = load_target_profile(
        profile_path=args.profile,
        analysis_json=args.analysis_json,
        xbe_path=args.xbe,
    )
    output = write_c_header(profile, args.output)
    print(
        json.dumps(
            {
                "status": "ok",
                "profile_id": profile.profile_id,
                "output": str(output),
                "special_functions": len(profile.special_functions),
            },
            sort_keys=True,
        )
    )
    return 0


def _run_validate(args: argparse.Namespace) -> int:
    """Execute the profile-validation subcommand."""
    profile = load_target_profile(
        profile_path=args.profile,
        analysis_json=args.analysis_json,
        xbe_path=args.xbe,
    )
    print(
        json.dumps(
            {
                "status": "ok",
                "profile_id": profile.profile_id,
                "title": profile.title,
                "entry_point": _format_hex(profile.entry_point),
                "kernel_thunk_address": _format_hex(profile.kernel_thunk_address),
                "sections": len(profile.sections),
                "code_sections": len(profile.code_sections),
                "data_sections": len(profile.data_sections),
                "special_functions": {
                    key: _format_hex(value)
                    for key, value in sorted(profile.special_functions.items())
                },
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the target-profile CLI and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            return _run_generate(args)
        if args.command == "validate":
            return _run_validate(args)
        if args.command == "emit-c-header":
            return _run_emit_c_header(args)
        parser.error(f"unsupported command: {args.command}")
    except TargetProfileError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
