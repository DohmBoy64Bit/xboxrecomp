"""Cross-check every active kernel ordinal surface against parser metadata."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from tools.xbe_parser.xbe_parser import KERNEL_EXPORTS


REPO_ROOT = Path(__file__).resolve().parents[1]
KERNEL_THUNKS = REPO_ROOT / "src" / "kernel" / "kernel_thunks.c"
KERNEL_BRIDGE = REPO_ROOT / "src" / "kernel" / "kernel_bridge.c"
KERNEL_HEADER = REPO_ROOT / "src" / "kernel" / "kernel.h"
KERNEL_DOC = REPO_ROOT / "docs" / "formats" / "kernel-exports.md"


class KernelOrdinalConsistencyTests(unittest.TestCase):
    """Ensure exact title ordinals cannot route through stale shifted tables."""

    @staticmethod
    def _read(path: Path) -> str:
        """Return UTF-8 source text for one repository path."""
        return path.read_text(encoding="utf-8")

    def test_compatibility_table_matches_parser(self) -> None:
        """Require every active compatibility case comment to match its ordinal."""
        text = self._read(KERNEL_THUNKS)
        start = text.index("ULONG_PTR xbox_resolve_ordinal")
        end = text.index("/* ============================================================================\n * Unresolved Thunk Handler")
        block = text[start:end]
        entries = re.findall(
            r"case\s+(\d+):\s+return\s+.*?/\*\s*([A-Za-z0-9_]+)\s*\*/",
            block,
        )
        self.assertGreater(len(entries), 100)
        mismatches = [
            (int(ordinal), name, KERNEL_EXPORTS.get(int(ordinal)))
            for ordinal, name in entries
            if KERNEL_EXPORTS.get(int(ordinal)) != name
        ]
        self.assertEqual([], mismatches)

    def test_stack_cleanup_table_matches_parser(self) -> None:
        """Require every named stdcall cleanup row to use the parser ordinal."""
        text = self._read(KERNEL_BRIDGE)
        start = text.index("static int stdcall_args_for_ordinal")
        end = text.index("static bridge_func_t bridge_for_ordinal")
        block = text[start:end]
        entries = re.findall(
            r"case\s+(\d+):\s+return\s+\d+;\s*/\*\s*([A-Za-z0-9_]+)",
            block,
        )
        self.assertGreater(len(entries), 100)
        mismatches = [
            (int(ordinal), name, KERNEL_EXPORTS.get(int(ordinal)))
            for ordinal, name in entries
            if KERNEL_EXPORTS.get(int(ordinal)) != name
        ]
        self.assertEqual([], mismatches)

    def test_bridge_dispatch_matches_parser(self) -> None:
        """Require each active bridge function to dispatch from its exact ordinal."""
        text = self._read(KERNEL_BRIDGE)
        start = text.index("static bridge_func_t bridge_for_ordinal")
        end = text.index("/* ── Per-slot bridge functions")
        block = text[start:end]
        entries = re.findall(
            r"case\s+(\d+):\s+return\s+bridge_([A-Za-z0-9_]+);",
            block,
        )
        aliases = {(150, "KeSetTimer"): "KeSetTimerEx"}
        mismatches = []
        for raw_ordinal, bridge_name in entries:
            ordinal = int(raw_ordinal)
            expected = aliases.get((ordinal, bridge_name), bridge_name)
            parser_name = KERNEL_EXPORTS.get(ordinal)
            if parser_name != expected:
                mismatches.append((ordinal, bridge_name, parser_name))
        self.assertEqual([], mismatches)

    def test_runtime_data_exports_match_parser(self) -> None:
        """Require runtime data slots to use the exact exported symbol ordinals."""
        text = self._read(KERNEL_BRIDGE)
        start = text.index("static uint32_t kernel_data_va_for_ordinal")
        end = text.index("/**\n * Initialize kernel data export values")
        block = text[start:end]
        constant_names = {
            "KDATA_EVENT_OBJ_TYPE": "ExEventObjectType",
            "KDATA_IO_COMPLETION_TYPE": "IoCompletionObjectType",
            "KDATA_IO_DEVICE_TYPE": "IoDeviceObjectType",
            "KDATA_TICK_COUNT": "KeTickCount",
            "KDATA_LAUNCH_DATA_PAGE": "LaunchDataPage",
            "KDATA_THREAD_OBJ_TYPE": "PsThreadObjectType",
            "KDATA_EEPROM_KEY": "XboxEEPROMKey",
            "KDATA_HARDWARE_INFO": "XboxHardwareInfo",
            "KDATA_HD_KEY": "XboxHDKey",
            "KDATA_KRNL_VERSION": "XboxKrnlVersion",
            "KDATA_SIGNATURE_KEY": "XboxSignatureKey",
            "KDATA_XE_IMAGE_FILENAME": "XeImageFileName",
            "KDATA_LAN_KEY": "XboxLANKey",
            "KDATA_ALT_SIGNATURE_KEYS": "XboxAlternateSignatureKeys",
            "KDATA_XE_PUBLIC_KEY": "XePublicKeyData",
        }
        entries = re.findall(
            r"case\s+(\d+):\s+return\s+XBOX_KERNEL_DATA_BASE\s*\+\s*(KDATA_[A-Z0-9_]+)",
            block,
        )
        self.assertEqual(set(constant_names), {constant for _, constant in entries})
        mismatches = [
            (int(ordinal), constant_names[constant], KERNEL_EXPORTS.get(int(ordinal)))
            for ordinal, constant in entries
            if KERNEL_EXPORTS.get(int(ordinal)) != constant_names[constant]
        ]
        self.assertEqual([], mismatches)

    def test_export_table_bounds_cover_all_ordinals(self) -> None:
        """Require C table bounds to include the parser's highest known ordinal."""
        text = self._read(KERNEL_HEADER)
        match = re.search(r"#define\s+XBOX_KERNEL_MAX_ORDINAL\s+(\d+)u", text)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(int(match.group(1)), max(KERNEL_EXPORTS))
        slots = re.search(r"#define\s+XBOX_KERNEL_MAX_THUNK_SLOTS\s+(\d+)u", text)
        self.assertIsNotNone(slots)
        self.assertGreaterEqual(int(slots.group(1)), max(KERNEL_EXPORTS))

    def test_documented_ordinals_match_parser(self) -> None:
        """Require every named ordinal table row in the guide to match the parser."""
        text = self._read(KERNEL_DOC)
        reverse = {name: ordinal for ordinal, name in KERNEL_EXPORTS.items()}
        unknown_names = []
        mismatches = []
        for line in text.splitlines():
            row = re.match(r"\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|", line)
            if not row:
                continue
            ordinal = int(row.group(1))
            declaration = row.group(2)
            function = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", declaration)
            if function:
                name = function.group(1)
            else:
                identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", declaration)
                if not identifiers:
                    continue
                name = identifiers[-1]
            expected = reverse.get(name)
            if expected is None:
                unknown_names.append((ordinal, name, declaration))
            elif expected != ordinal:
                mismatches.append((ordinal, name, expected))
        self.assertEqual([], unknown_names)
        self.assertEqual([], mismatches)


if __name__ == "__main__":
    unittest.main()
