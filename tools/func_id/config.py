"""Target-neutral configuration for function identification.

Address ranges are populated from :class:`tools.target_profile.TargetProfile`
before any analysis phase runs.  Static signature and confidence tables remain
here because they are algorithm configuration rather than title addresses.
"""

from __future__ import annotations

from tools.target_profile import SectionProfile, TargetProfile

ACTIVE_PROFILE: TargetProfile | None = None
XBE_BASE_ADDRESS = 0
TEXT_VA_START = 0
TEXT_VA_SIZE = 0
TEXT_VA_END = 0
TEXT_RAW_ADDR = 0
RDATA_VA_START = 0
RDATA_VA_SIZE = 0
RDATA_VA_END = 0
RDATA_RAW_ADDR = 0
DATA_VA_START = 0
DATA_VA_SIZE = 0
DATA_VA_END = 0
DATA_RAW_ADDR = 0
SECTIONS: list[tuple[str, int, int, int]] = []
XDK_SECTIONS: dict[str, tuple[int, int, str]] = {}
GAME_SUBCATEGORIES: dict[str, list[str]] = {}


def configure_target(profile: TargetProfile) -> None:
    """Populate compatibility fields from an explicit target profile."""
    global ACTIVE_PROFILE
    global XBE_BASE_ADDRESS
    global TEXT_VA_START, TEXT_VA_SIZE, TEXT_VA_END, TEXT_RAW_ADDR
    global RDATA_VA_START, RDATA_VA_SIZE, RDATA_VA_END, RDATA_RAW_ADDR
    global DATA_VA_START, DATA_VA_SIZE, DATA_VA_END, DATA_RAW_ADDR
    global SECTIONS, XDK_SECTIONS, GAME_SUBCATEGORIES

    ACTIVE_PROFILE = profile
    XBE_BASE_ADDRESS = profile.base_address
    primary = profile.primary_code_section
    TEXT_VA_START = primary.virtual_address
    TEXT_VA_SIZE = primary.virtual_size
    TEXT_VA_END = primary.virtual_end
    TEXT_RAW_ADDR = primary.raw_address

    read_only = profile.primary_read_only_section
    data_sections = profile.data_sections
    writable = next((section for section in data_sections if section.writable), None)
    fallback = read_only or writable or (data_sections[0] if data_sections else None)
    if fallback is None:
        RDATA_VA_START = RDATA_VA_SIZE = RDATA_VA_END = RDATA_RAW_ADDR = 0
        DATA_VA_START = DATA_VA_SIZE = DATA_VA_END = DATA_RAW_ADDR = 0
    else:
        read_only = read_only or fallback
        writable = writable or fallback
        RDATA_VA_START = read_only.virtual_address
        RDATA_VA_SIZE = read_only.virtual_size
        RDATA_VA_END = read_only.virtual_end
        RDATA_RAW_ADDR = read_only.raw_address
        DATA_VA_START = writable.virtual_address
        DATA_VA_SIZE = writable.virtual_size
        DATA_VA_END = writable.virtual_end
        DATA_RAW_ADDR = writable.raw_address

    SECTIONS = [
        (section.name, section.virtual_address, section.virtual_size, section.raw_address)
        for section in profile.sections
    ]
    XDK_SECTIONS = dict(profile.xdk_sections)
    GAME_SUBCATEGORIES = {
        category: list(keywords)
        for category, keywords in (profile.game_subcategories or {}).items()
    }


def require_target() -> TargetProfile:
    """Return the active profile or fail before target-bound analysis starts."""
    if ACTIVE_PROFILE is None:
        raise RuntimeError(
            "function identification has no target profile; pass --analysis-json "
            "and/or --target-profile"
        )
    return ACTIVE_PROFILE


def va_to_file_offset(va: int) -> int | None:
    """Convert a virtual address using the active target's exact section map."""
    return require_target().virtual_to_file_offset(va)


def is_code_address(va: int) -> bool:
    """Return whether an address belongs to approved target code."""
    return require_target().is_code_address(va)


def is_data_address(va: int) -> bool:
    """Return whether an address belongs to approved target data."""
    return require_target().is_data_address(va)


def code_sections() -> tuple[SectionProfile, ...]:
    """Return all approved code sections for the active target."""
    return require_target().code_sections


def data_sections() -> tuple[SectionProfile, ...]:
    """Return all approved data sections for the active target."""
    return require_target().data_sections

# ============================================================
# CRT Byte Signatures
# ============================================================
# Each entry: (name, pattern_bytes, mask_bytes_or_None, max_func_size)
# mask: 0xFF = must match, 0x00 = wildcard
# max_func_size: upper bound on expected function size (0 = no check)

CRT_SIGNATURES = [
    # memcpy - push ebp; mov ebp,esp; push edi; push esi; mov esi,[ebp+0C]; mov edi,[ebp+08]; mov ecx,[ebp+10]
    ("memcpy",
     bytes([0x55, 0x8B, 0xEC, 0x57, 0x56, 0x8B, 0x75, 0x0C, 0x8B, 0x7D, 0x08, 0x8B, 0x4D, 0x10]),
     None, 512),

    # memset - push ebp; mov ebp,esp; push edi; mov edi,[ebp+08]; mov eax,[ebp+0C]; mov ecx,[ebp+10]
    ("memset",
     bytes([0x55, 0x8B, 0xEC, 0x57, 0x8B, 0x7D, 0x08, 0x8B, 0x45, 0x0C, 0x8B, 0x4D, 0x10]),
     None, 256),

    # strlen - mov ecx,[esp+04]; test ecx,03
    ("strlen",
     bytes([0x8B, 0x4C, 0x24, 0x04, 0xF7, 0xC1, 0x03, 0x00, 0x00, 0x00]),
     None, 256),

    # strcmp - push esi; mov esi,[esp+08]; push edi; mov edi,[esp+10]
    ("strcmp",
     bytes([0x56, 0x8B, 0x74, 0x24, 0x08, 0x57, 0x8B, 0x7C, 0x24, 0x10]),
     None, 256),

    # strncmp - push edi; push esi; mov edi,[esp+10]; mov esi,[esp+0C]; mov ecx,[esp+14]
    ("strncmp",
     bytes([0x57, 0x56, 0x8B, 0x7C, 0x24, 0x10, 0x8B, 0x74, 0x24, 0x0C, 0x8B, 0x4C, 0x24, 0x14]),
     None, 256),

    # strcpy - push esi; mov esi,[esp+0C]; push edi; mov edi,[esp+0C]
    ("strcpy",
     bytes([0x56, 0x8B, 0x74, 0x24, 0x0C, 0x57, 0x8B, 0x7C, 0x24, 0x0C]),
     None, 256),

    # _ftol - MSVC float-to-long: fnstcw [esp-2]; ...
    ("_ftol",
     bytes([0xD9, 0x44, 0x24, 0x00]),
     bytes([0xFF, 0xFF, 0xFF, 0x00]),
     64),

    # _ftol2 - push ebp; mov ebp,esp; sub esp,20; and esp,F0
    ("_ftol2",
     bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x83, 0xE4, 0xF0]),
     None, 128),

    # _chkstk - push ecx; cmp eax,1000
    ("_chkstk",
     bytes([0x51, 0x3D, 0x00, 0x10, 0x00, 0x00]),
     None, 64),

    # _alloca_probe - push ecx; cmp eax,1000  (same as _chkstk on Xbox)
    ("_alloca_probe",
     bytes([0x51, 0x3D, 0x00, 0x10, 0x00, 0x00]),
     None, 64),

    # _allmul - 64-bit multiply: mov eax,[esp+08]; mov ecx,[esp+10]
    ("_allmul",
     bytes([0x8B, 0x44, 0x24, 0x08, 0x8B, 0x4C, 0x24, 0x10]),
     None, 128),

    # _alldiv - 64-bit divide: push edi; push esi; push ebx
    ("_alldiv",
     bytes([0x57, 0x56, 0x53, 0x33, 0xFF, 0x8B, 0x44, 0x24, 0x14]),
     None, 256),

    # _allrem - 64-bit remainder: push edi; push esi; push ebx
    ("_allrem",
     bytes([0x57, 0x56, 0x53, 0x33, 0xFF, 0x8B, 0x4C, 0x24, 0x18]),
     None, 256),

    # _aullshr - 64-bit unsigned shift right: cmp cl,40
    ("_aullshr",
     bytes([0x80, 0xF9, 0x40, 0x73]),
     None, 48),

    # _allshr - 64-bit signed shift right: cmp cl,40
    ("_allshr",
     bytes([0x80, 0xF9, 0x40, 0x73]),
     None, 48),

    # _allshl - 64-bit shift left: cmp cl,40
    ("_allshl",
     bytes([0x80, 0xF9, 0x40, 0x73]),
     None, 48),

    # _purecall - push ... ; call ... (typically just calls an error handler)
    # push 0x19 (STATUS_NOT_IMPLEMENTED); call RtlRaiseStatus
    ("_purecall",
     bytes([0x6A, 0x19]),
     None, 16),

    # memmove - push ebp; mov ebp,esp; push edi; push esi; mov esi,[ebp+0C]; mov ecx,[ebp+10]; mov edi,[ebp+08]
    ("memmove",
     bytes([0x55, 0x8B, 0xEC, 0x57, 0x56, 0x8B, 0x75, 0x0C, 0x8B, 0x4D, 0x10, 0x8B, 0x7D, 0x08]),
     None, 512),

    # memcmp - push ebp; mov ebp,esp; push esi; push edi; mov esi,[ebp+08]; mov edi,[ebp+0C]; mov ecx,[ebp+10]
    ("memcmp",
     bytes([0x55, 0x8B, 0xEC, 0x56, 0x57, 0x8B, 0x75, 0x08, 0x8B, 0x7D, 0x0C, 0x8B, 0x4D, 0x10]),
     None, 256),

    # strcat - mov ecx,[esp+04]; push edi; test ecx,03
    ("strcat",
     bytes([0x8B, 0x4C, 0x24, 0x04, 0x57, 0xF7, 0xC1, 0x03, 0x00, 0x00, 0x00]),
     None, 256),

    # _CIcos - fcos; ret
    ("_CIcos",
     bytes([0xD9, 0xFF, 0xC3]),
     None, 8),

    # _CIsin - fsin; ret
    ("_CIsin",
     bytes([0xD9, 0xFE, 0xC3]),
     None, 8),

    # _CIsqrt - fsqrt; ret
    ("_CIsqrt",
     bytes([0xD9, 0xFA, 0xC3]),
     None, 8),

    # _fmod - MSVC fmod: push ebp; mov ebp,esp; sub esp,0C
    ("fmod",
     bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C]),
     None, 256),

    # sprintf / _sprintf - push ebp; mov ebp,esp; lea eax,[ebp+10]
    ("sprintf",
     bytes([0x55, 0x8B, 0xEC, 0x8D, 0x45, 0x10]),
     None, 128),
]

# ============================================================
# Confidence Thresholds
# ============================================================

CONFIDENCE_RW_STRING_REF = 0.95    # Function directly references an RW ID string
CONFIDENCE_RW_ZONE = 0.85          # Function references data in an RW .rdata zone
CONFIDENCE_CRT_SIGNATURE = 0.90    # CRT byte-pattern match
CONFIDENCE_CLUSTER_CALL = 0.75     # Label propagation via call graph
CONFIDENCE_CLUSTER_PROXIMITY = 0.65  # Label propagation via address proximity

# Maximum address gap for proximity clustering
PROXIMITY_GAP = 0x1000

# Maximum clustering iterations
MAX_CLUSTER_ITERATIONS = 10

# ============================================================
# RenderWare Module Categories
# ============================================================

RW_CATEGORIES = {
    "src/plcore/":       "rw_plcore",
    "src/pipe/p2/xbox/": "rw_pipe_xbox",
    "src/pipe/p2/":      "rw_pipe",
    "driver/xbox/":      "rw_driver_xbox",
    "driver/common/":    "rw_driver_common",
    "os/xbox/":          "rw_os_xbox",
    "world/pipe/p2/xbox/": "rw_world_pipe_xbox",
    "world/pipe/p2/":    "rw_world_pipe",
    "world/":            "rw_world",
    "src/":              "rw_core",
}

# ============================================================
# Game Sub-classification Keywords
# ============================================================

# Populated from the selected target profile. Analysis-only profiles leave
# this empty rather than inheriting Burnout-specific vocabulary.
GAME_SUBCATEGORIES = {}
