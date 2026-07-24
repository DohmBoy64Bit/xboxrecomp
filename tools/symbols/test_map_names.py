"""Self-checks for exact-target MAP parsing and name porting.

Run directly with ``python tools/symbols/test_map_names.py``. The fixtures are
synthetic and contain no game data.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

if __package__:
    from .map_names import check_entry, parse_map, port_names, va_to_off
else:
    from map_names import check_entry, parse_map, port_names, va_to_off

from tools.target_profile import profile_from_analysis


# A title with .text at 0x11000 and an XDK section at 0x50000, mirroring the
# real layout: MAP section 0001 -> XBE section 0.
SECTIONS = [
    (".text", 0x11000, 0x2000, 0x1000, 0x2000),
    ("DSOUND", 0x50000, 0x1000, 0x3000, 0x1000),
]

MAP_TEXT = """\
 Default

 Preferred load address is 00400000

 Start         Length     Name                   Class
 0001:00000000 00001000H .text                   CODE
 0002:00000000 00001000H DSOUND                  CODE

  Address         Publics by Value              Rva+Base     Lib:Object
 0000:00000000       ___safe_se_handler_count   00000000     <absolute>
 0001:00000000       ?first@@YAXXZ              00400700 f i A.obj
 0001:00000100       ?second@@YAXXZ              00400800 f i A.obj
 0002:00000040       _DirectSoundCreate@8       00420000 f i DSOUND.lib

 entry point at        0001:00000100
"""


def sample_profile(entry_point: int = 0x00011100):
    """Return a profile matching the synthetic MAP/XBE section layout."""
    return profile_from_analysis({
        "title": "Synthetic MAP Test",
        "base_address": "0x00010000",
        "image_size": 0x51000,
        "entry_point": f"0x{entry_point:08X}",
        "kernel_thunk_addr": "0x00011000",
        "sections": [
            {
                "name": name,
                "virtual_addr": f"0x{virtual_address:08X}",
                "virtual_size": virtual_size,
                "raw_addr": f"0x{raw_address:08X}",
                "raw_size": raw_size,
                "executable": True,
                "writable": False,
            }
            for name, virtual_address, virtual_size, raw_address, raw_size in SECTIONS
        ],
    })


def test_parse() -> None:
    """Resolve MAP section offsets against XBE section order."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "test.map"
        path.write_text(MAP_TEXT, encoding="utf-8")
        symbols, entry = parse_map(path, SECTIONS)

    assert symbols[0x11000] == "?first@@YAXXZ", symbols
    assert symbols[0x11100] == "?second@@YAXXZ", symbols
    assert symbols[0x50040] == "_DirectSoundCreate@8", symbols
    assert not any(address < 0x11000 for address in symbols), symbols
    assert entry == 0x11100, hex(entry or 0)
    assert 0x400800 not in symbols
    print("ok  parse_map: section:offset -> XBE VA, entry point, absolutes dropped")


def test_va_to_off() -> None:
    """Translate only raw-backed virtual addresses into XBE offsets."""
    assert va_to_off(SECTIONS, 0x11000) == 0x1000
    assert va_to_off(SECTIONS, 0x11010) == 0x1010
    assert va_to_off(SECTIONS, 0x50040) == 0x3040
    assert va_to_off(SECTIONS, 0x99999) is None
    print("ok  va_to_off")


def test_port() -> None:
    """Port only unique, non-padding signatures at validated starts."""
    body = bytes(range(0x40)) + b"\x55\x8b\xec\x83\xec\x10\x90\x91\x92\x93\x94\x95" + b"\x00" * 0x40
    donor_raw = b"\x00" * 0x3000 + body
    donor_symbols = {0x50040: "_DirectSoundCreate@8"}

    target_sections = [("DSOUND", 0x60000, 0x1000, 0x100, 0x1000)]
    target_raw = b"\x00" * 0x100 + bytes(0x40) + body[0x40:] + b"\x00" * 0x100

    names, stats = port_names(
        donor_raw,
        SECTIONS,
        donor_symbols,
        target_raw,
        target_sections,
        {0x60040},
        {"DSOUND"},
        12,
    )
    assert names == {0x60040: "_DirectSoundCreate@8"}, (names, stats)
    print("ok  port_names: matches library code at a different address")

    names, stats = port_names(
        donor_raw,
        SECTIONS,
        donor_symbols,
        target_raw,
        target_sections,
        set(),
        {"DSOUND"},
        12,
    )
    assert names == {}, names
    assert stats["off_start"] == 1, stats
    print("ok  port_names: drops matches that are not function starts")

    names, stats = port_names(
        b"\x00" * 0x4000,
        SECTIONS,
        {0x50040: "pad"},
        target_raw,
        target_sections,
        {0x60040},
        {"DSOUND"},
        12,
    )
    assert names == {} and stats["unusable"] == 1, stats
    print("ok  port_names: rejects zero-filled signatures")


def test_check_entry() -> None:
    """Require a MAP entry point that exactly matches the selected profile."""
    profile = sample_profile()
    assert check_entry(0x11100, profile, "synthetic") is True
    assert check_entry(0x21CDA2, profile, "synthetic") is False
    assert check_entry(None, profile, "synthetic") is False
    print("ok  check_entry: requires a present, exact-build entry point")


if __name__ == "__main__":
    test_parse()
    test_va_to_off()
    test_port()
    test_check_entry()
    print("\nall passed")
