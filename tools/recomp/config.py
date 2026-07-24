"""Compatibility adapter for the explicit recompiler target profile.

New code should pass :class:`tools.target_profile.TargetProfile` directly.
This module keeps the historical helper names available without retaining any
Burnout 3 or Xbox Dashboard fallback addresses.
"""

from __future__ import annotations

from tools.target_profile import TargetProfile

ACTIVE_PROFILE: TargetProfile | None = None
SECTIONS: list[tuple[str, int, int, int]] = []
TEXT_VA_START = 0
TEXT_VA_END = 0
RDATA_VA_START = 0
RDATA_VA_END = 0
DATA_VA_START = 0
DATA_VA_END = 0
KERNEL_THUNK_ADDR = 0
ENTRY_POINT = 0


def configure_target(profile: TargetProfile) -> None:
    """Populate legacy compatibility fields from an explicit profile."""
    global ACTIVE_PROFILE, SECTIONS
    global TEXT_VA_START, TEXT_VA_END
    global RDATA_VA_START, RDATA_VA_END
    global DATA_VA_START, DATA_VA_END
    global KERNEL_THUNK_ADDR, ENTRY_POINT

    ACTIVE_PROFILE = profile
    SECTIONS = [
        (section.name, section.virtual_address, section.virtual_size, section.raw_address)
        for section in profile.sections
    ]
    primary = profile.primary_code_section
    TEXT_VA_START = primary.virtual_address
    TEXT_VA_END = primary.virtual_end
    read_only = profile.primary_read_only_section
    writable = next((section for section in profile.data_sections if section.writable), None)
    RDATA_VA_START = read_only.virtual_address if read_only else 0
    RDATA_VA_END = read_only.virtual_end if read_only else 0
    DATA_VA_START = writable.virtual_address if writable else RDATA_VA_START
    DATA_VA_END = writable.virtual_end if writable else RDATA_VA_END
    KERNEL_THUNK_ADDR = profile.kernel_thunk_address
    ENTRY_POINT = profile.entry_point


def require_target() -> TargetProfile:
    """Return the active profile or reject target-ambiguous use."""
    if ACTIVE_PROFILE is None:
        raise RuntimeError(
            "recompiler target is not configured; pass --analysis-json and/or "
            "--target-profile"
        )
    return ACTIVE_PROFILE


def va_to_file_offset(va: int) -> int | None:
    """Convert a virtual address using the active target profile."""
    return require_target().virtual_to_file_offset(va)


def is_code_address(va: int) -> bool:
    """Return whether a virtual address belongs to approved target code."""
    return require_target().is_code_address(va)


def is_data_address(va: int) -> bool:
    """Return whether a virtual address belongs to approved target data."""
    return require_target().is_data_address(va)
