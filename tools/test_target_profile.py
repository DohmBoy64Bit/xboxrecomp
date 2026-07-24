"""Tests for explicit per-title target-profile loading and validation."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.disasm.cache import AnalysisCache
from tools.disasm.disasm import Disassembler
from tools.func_id import config as func_id_config
from tools.func_id.vtable_scanner import scan_vtables
from tools.recomp.lifter import Lifter
from tools.recomp.translator import BatchTranslator
from tools.target_profile import (
    TargetProfileError,
    load_target_profile,
    profile_from_analysis,
    render_c_header,
    write_target_profile,
)


def sample_analysis() -> dict[str, object]:
    """Return a minimal parser-analysis object for a fictional title."""
    return {
        "title": "Laylat Wars",
        "base_address": "0x00010000",
        "image_size": 0x5000,
        "entry_point": "0x00011010",
        "kernel_thunk_addr": "0x00013000",
        "sections": [
            {
                "name": ".text",
                "virtual_addr": "0x00011000",
                "virtual_size": 0x1000,
                "raw_addr": "0x00001000",
                "raw_size": 0x1000,
                "executable": True,
                "writable": False,
            },
            {
                "name": "LWSCRIPT",
                "virtual_addr": "0x00012000",
                "virtual_size": 0x1000,
                "raw_addr": "0x00002000",
                "raw_size": 0x1000,
                "executable": False,
                "writable": False,
            },
            {
                "name": ".rdata",
                "virtual_addr": "0x00013000",
                "virtual_size": 0x1000,
                "raw_addr": "0x00003000",
                "raw_size": 0x1000,
                "executable": False,
                "writable": False,
            },
        ],
    }

def sample_xbe_bytes() -> bytes:
    """Return minimal retail XBE bytes matching :func:`sample_analysis`."""
    raw = bytearray(0x4000)
    raw[:4] = b"XBEH"
    base = 0x00010000
    section_headers_offset = 0x0200
    section_names_offset = 0x0500
    struct.pack_into("<I", raw, 0x0104, base)
    struct.pack_into("<I", raw, 0x010C, 0x00005000)
    struct.pack_into("<I", raw, 0x011C, 3)
    struct.pack_into("<I", raw, 0x0120, base + section_headers_offset)
    struct.pack_into("<I", raw, 0x0128, 0x00011010 ^ 0xA8FC57AB)
    struct.pack_into("<I", raw, 0x0158, 0x00013000 ^ 0x5B6D40B6)

    sections = (
        (".text", 0x4, 0x00011000, 0x1000, 0x1000, 0x1000),
        ("LWSCRIPT", 0x0, 0x00012000, 0x1000, 0x2000, 0x1000),
        (".rdata", 0x0, 0x00013000, 0x1000, 0x3000, 0x1000),
    )
    name_cursor = section_names_offset
    for index, (name, flags, va, vsize, raw_address, raw_size) in enumerate(sections):
        encoded = name.encode("ascii") + b"\0"
        raw[name_cursor:name_cursor + len(encoded)] = encoded
        header_offset = section_headers_offset + index * 56
        struct.pack_into(
            "<IIIIII", raw, header_offset, flags, va, vsize,
            raw_address, raw_size, base + name_cursor,
        )
        name_cursor += len(encoded)
    return bytes(raw)


class TargetProfileTests(unittest.TestCase):
    """Verify that target-bound values are explicit and cross-checked."""

    def test_analysis_only_profile_is_target_specific(self) -> None:
        """Parser output should create a profile without reference-title data."""
        profile = profile_from_analysis(sample_analysis())
        self.assertEqual(profile.profile_id, "laylat-wars")
        self.assertEqual(profile.entry_point, 0x00011010)
        self.assertEqual(profile.special_functions, {})
        self.assertFalse(profile.renderware_identification)

    def test_missing_target_input_fails_closed(self) -> None:
        """No tool may select Burnout or Dashboard addresses implicitly."""
        with self.assertRaisesRegex(TargetProfileError, "required"):
            load_target_profile()

    def test_disassembler_requires_explicit_output_directory(self) -> None:
        """Direct API use must not write into a repository-global output path."""
        with self.assertRaisesRegex(ValueError, "explicit target-specific output"):
            Disassembler("default.xbe", analysis_json="analysis.json")

    def test_disassembler_cross_checks_analysis_against_exact_xbe(self) -> None:
        """Analysis-only disassembly must reject JSON from a different binary."""
        analysis = sample_analysis()
        analysis["entry_point"] = "0x00011020"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            analysis_path = root / "analysis.json"
            xbe_path.write_bytes(sample_xbe_bytes())
            analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
            disassembler = Disassembler(
                str(xbe_path),
                analysis_json=str(analysis_path),
                output_dir=str(root / "disasm"),
            )
            with self.assertRaisesRegex(TargetProfileError, "profile/XBE mismatch"):
                disassembler.run()

    def test_batch_translator_requires_explicit_output_directory(self) -> None:
        """Direct recompiler use must not write into a shared output directory."""
        profile = profile_from_analysis(sample_analysis())
        with self.assertRaisesRegex(ValueError, "explicit target-specific output"):
            BatchTranslator("default.xbe", "functions.json", target_profile=profile)

    def test_profile_can_approve_nonstandard_code_without_rewriting_flags(self) -> None:
        """A profile role may approve code while preserving the XBE flag."""
        analysis = sample_analysis()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis_path = root / "analysis.json"
            profile_path = root / "profile.json"
            analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
            profile = profile_from_analysis(analysis)
            data = profile.to_dict()
            data["sections"][1]["role"] = "code"
            profile_path.write_text(json.dumps(data), encoding="utf-8")

            merged = load_target_profile(
                profile_path=profile_path,
                analysis_json=analysis_path,
            )

        section = merged.section_for_address(0x00012010)
        self.assertIsNotNone(section)
        assert section is not None
        self.assertFalse(section.executable)
        self.assertTrue(section.is_code)

    def test_profile_rejects_ambiguous_boolean_values(self) -> None:
        """Profile booleans must be real JSON booleans, not truthy strings."""
        profile_data = profile_from_analysis(sample_analysis()).to_dict()
        profile_data["sections"][0]["executable"] = "false"
        with tempfile.TemporaryDirectory() as directory:
            profile_path = Path(directory) / "profile.json"
            profile_path.write_text(json.dumps(profile_data), encoding="utf-8")
            with self.assertRaisesRegex(TargetProfileError, "must be a JSON boolean"):
                load_target_profile(profile_path=profile_path)

    def test_profile_analysis_address_mismatch_is_rejected(self) -> None:
        """A profile must not override immutable parser-derived coordinates."""
        analysis = sample_analysis()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis_path = root / "analysis.json"
            profile_path = root / "profile.json"
            analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
            profile = profile_from_analysis(analysis).to_dict()
            profile["entry_point"] = "0x00011020"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            with self.assertRaisesRegex(TargetProfileError, "mismatch"):
                load_target_profile(
                    profile_path=profile_path,
                    analysis_json=analysis_path,
                )

    def test_xbe_hash_and_raw_bounds_are_enforced(self) -> None:
        """Profile validation should bind to exact bytes when a hash is present."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            xbe_path.write_bytes(sample_xbe_bytes())
            profile = profile_from_analysis(sample_analysis()).to_dict()
            profile["xbe_sha256"] = "0" * 64
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            with self.assertRaisesRegex(TargetProfileError, "SHA-256 mismatch"):
                load_target_profile(profile_path=profile_path, xbe_path=xbe_path)



    def test_xbe_section_coordinates_are_cross_checked(self) -> None:
        """A profile cannot replace one title section map with another."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            xbe_path.write_bytes(sample_xbe_bytes())
            profile_data = profile_from_analysis(sample_analysis()).to_dict()
            profile_data["sections"][0]["virtual_size"] = 0x800
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile_data), encoding="utf-8")
            with self.assertRaisesRegex(TargetProfileError, "section mismatch"):
                load_target_profile(profile_path=profile_path, xbe_path=xbe_path)

    def test_xbe_immutable_header_mismatch_is_rejected(self) -> None:
        """Profile validation should reject an exact-XBE entry-point mismatch."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            raw = bytearray(sample_xbe_bytes())
            struct.pack_into("<I", raw, 0x0128, 0x00011020 ^ 0xA8FC57AB)
            xbe_path.write_bytes(raw)
            profile_path = root / "profile.json"
            write_target_profile(profile_from_analysis(sample_analysis()), profile_path)

            with self.assertRaisesRegex(TargetProfileError, "profile/XBE mismatch"):
                load_target_profile(profile_path=profile_path, xbe_path=xbe_path)

    def test_exact_xbe_hash_can_be_embedded(self) -> None:
        """A complete profile should preserve an exact-XBE SHA-256 binding."""
        raw = sample_xbe_bytes()
        profile = profile_from_analysis(sample_analysis())
        data = profile.to_dict()
        data["xbe_sha256"] = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            profile_path = root / "profile.json"
            xbe_path.write_bytes(raw)
            profile_path.write_text(json.dumps(data), encoding="utf-8")
            loaded = load_target_profile(profile_path=profile_path, xbe_path=xbe_path)

        self.assertEqual(loaded.xbe_sha256, hashlib.sha256(raw).hexdigest())

    def test_function_identifier_uses_selected_profile(self) -> None:
        """Function-identification compatibility fields should follow the profile."""
        profile = profile_from_analysis(sample_analysis())
        func_id_config.configure_target(profile)
        self.assertTrue(func_id_config.is_code_address(0x00011020))
        self.assertFalse(func_id_config.is_code_address(0x00012020))
        self.assertTrue(func_id_config.is_data_address(0x00013020))

    def test_generated_c_header_contains_validated_identity(self) -> None:
        """The generated runtime header should expose only selected target data."""
        header = render_c_header(profile_from_analysis(sample_analysis()))
        self.assertIn('#define XBOX_TARGET_TITLE "Laylat Wars"', header)
        self.assertIn('#define XBOX_TARGET_ENTRY_POINT 0x00011010u', header)
        self.assertIn("XBOX_TARGET_IS_CODE_ADDRESS", header)
        self.assertIn("xbox_target_va_to_file_offset", header)
        self.assertIn("*file_offset = 0x00001000u", header)
        self.assertIn("address - 0x00011000u", header)
        self.assertIn("0x00011000u", header)
        self.assertIn("0x00012000u", header)
        self.assertNotIn("0x00400000", header)
        self.assertNotIn("Burnout", header)
        self.assertNotIn("Dashboard", header)

    def test_code_range_validation_rejects_data_and_boundary_crossing(self) -> None:
        """Function databases must stay inside one profile-approved code section."""
        profile = profile_from_analysis(sample_analysis())
        profile.validate_code_range(0x00011010, 0x00011020, "valid")
        with self.assertRaisesRegex(TargetProfileError, "outside approved code"):
            profile.validate_code_range(0x00012010, 0x00012020, "data")
        with self.assertRaisesRegex(TargetProfileError, "crosses the .text"):
            profile.validate_code_range(0x00011FF0, 0x00012010, "crossing")

    def test_batch_translator_rejects_wrong_target_function_database(self) -> None:
        """The recompiler must reject a function database from another target."""
        profile = profile_from_analysis(sample_analysis())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            functions_path = root / "functions.json"
            xbe_path.write_bytes(sample_xbe_bytes())
            functions_path.write_text(
                json.dumps([{
                    "start": "0x00012010",
                    "end": "0x00012020",
                    "size": 0x10,
                }]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(TargetProfileError, "outside approved code"):
                BatchTranslator(
                    str(xbe_path),
                    str(functions_path),
                    output_dir=str(root / "output"),
                    target_profile=profile,
                )


    def test_batch_translator_rejects_wrong_target_abi_database(self) -> None:
        """ABI records must belong to a function in the selected target database."""
        profile = profile_from_analysis(sample_analysis())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            functions_path = root / "functions.json"
            abi_path = root / "abi.json"
            xbe_path.write_bytes(sample_xbe_bytes())
            functions_path.write_text(
                json.dumps([{
                    "start": "0x00011010",
                    "end": "0x00011020",
                    "size": 0x10,
                }]),
                encoding="utf-8",
            )
            abi_path.write_text(
                json.dumps([{"address": "0x00012010", "calling_convention": "cdecl"}]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(TargetProfileError, "absent from functions.json"):
                BatchTranslator(
                    str(xbe_path),
                    str(functions_path),
                    abi_json_path=str(abi_path),
                    output_dir=str(root / "output"),
                    target_profile=profile,
                )


    def test_disassembly_cache_includes_profile_bytes(self) -> None:
        """Changing a target profile must invalidate cached disassembly."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            xbe_path = root / "default.xbe"
            analysis_path = root / "analysis.json"
            profile_path = root / "profile.json"
            xbe_path.write_bytes(sample_xbe_bytes())
            analysis_path.write_text(json.dumps(sample_analysis()), encoding="utf-8")
            write_target_profile(profile_from_analysis(sample_analysis()), profile_path)
            for name in ("summary.json", "functions.json", "xrefs.json",
                         "strings.json", "labels.json"):
                (output / name).write_text("{}", encoding="utf-8")
            cache = AnalysisCache(str(output))
            cache.save(
                str(xbe_path), str(analysis_path), False, 1.0,
                target_profile_path=str(profile_path),
            )
            self.assertTrue(cache.is_valid(
                str(xbe_path), str(analysis_path),
                target_profile_path=str(profile_path),
            ))
            profile_data = json.loads(profile_path.read_text(encoding="utf-8"))
            profile_data["sections"][1]["role"] = "code"
            profile_path.write_text(json.dumps(profile_data), encoding="utf-8")
            self.assertFalse(cache.is_valid(
                str(xbe_path), str(analysis_path),
                target_profile_path=str(profile_path),
            ))

    def test_vtable_scan_accepts_every_profile_code_section(self) -> None:
        """Vtable targets may live in approved code sections outside .text."""
        raw = bytearray(0x400)
        struct.pack_into("<III", raw, 0x200, 0x00012010, 0x00012020, 0x00012030)
        sections = [
            {"name": ".text", "va": 0x00011000, "size": 0x100,
             "raw": 0x100, "raw_size": 0x100, "executable": True},
            {"name": "LWSCRIPT", "va": 0x00012000, "size": 0x100,
             "raw": 0x180, "raw_size": 0x80, "executable": True},
            {"name": ".rdata", "va": 0x00013000, "size": 0x100,
             "raw": 0x200, "raw_size": 0x100, "executable": False},
        ]
        functions = [
            {"start": f"0x{address:08X}", "end": f"0x{address + 4:08X}"}
            for address in (0x00012010, 0x00012020, 0x00012030)
        ]
        results, vtables = scan_vtables(bytes(raw), functions, {}, sections=sections)
        self.assertEqual(len(vtables), 1)
        self.assertEqual(set(results), {0x00012010, 0x00012020, 0x00012030})

    def test_recompiler_seh_helpers_come_only_from_profile(self) -> None:
        """The lifter must not inherit legacy SEH helper addresses."""
        profile_data = profile_from_analysis(sample_analysis()).to_dict()
        profile_data["special_functions"] = {
            "seh_prolog": "0x00011040",
            "seh_epilog": "0x00011080",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(profile_data), encoding="utf-8")
            profile = load_target_profile(profile_path=path)
        lifter = Lifter(target_profile=profile)
        self.assertTrue(lifter.is_seh_helper(0x00011040))
        self.assertFalse(lifter.is_seh_helper(0x00244784))

    def test_map_name_resolution_requires_exact_target_identity(self) -> None:
        """MAP resolution must bind the MAP, analysis JSON, and exact XBE."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            analysis_path = root / "analysis.json"
            map_path = root / "target.map"
            output_path = root / "map_names.json"
            xbe_path.write_bytes(sample_xbe_bytes())
            analysis_path.write_text(json.dumps(sample_analysis()), encoding="utf-8")
            map_path.write_text(
                " 0001:00000000 00001000H .text CODE\n"
                " entry point at 0001:00000010\n"
                " 0001:00000010 LaylatEntry 00011010 f i laylat.obj\n",
                encoding="utf-8",
            )
            script = Path(__file__).parent / "symbols" / "map_names.py"
            result = subprocess.run(
                [
                    sys.executable, str(script), "resolve",
                    str(map_path), str(analysis_path),
                    "--target-xbe", str(xbe_path),
                    "--output", str(output_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            names = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(names["0x00011010"], "LaylatEntry")

    def test_ghidra_name_apply_requires_and_uses_target_identity(self) -> None:
        """Ghidra names may only update a function DB validated for the target."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xbe_path = root / "default.xbe"
            analysis_path = root / "analysis.json"
            names_path = root / "names.json"
            functions_path = root / "functions.json"
            output_path = root / "ghidra_names.json"
            xbe_path.write_bytes(sample_xbe_bytes())
            analysis_path.write_text(json.dumps(sample_analysis()), encoding="utf-8")
            names_path.write_text(
                json.dumps({"0x00011010": "LaylatEntry"}), encoding="utf-8"
            )
            functions_path.write_text(
                json.dumps([{
                    "start": "0x00011010",
                    "end": "0x00011020",
                    "size": 0x10,
                }]),
                encoding="utf-8",
            )
            script = Path(__file__).parent / "ghidra_naming" / "merge_names.py"
            unbound = subprocess.run(
                [
                    sys.executable, str(script),
                    "--names-json", str(names_path),
                    "--out", str(output_path),
                    "--functions-json", str(functions_path),
                    "--apply",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(unbound.returncode, 2)
            self.assertIn("requires --target-profile or --analysis-json", unbound.stderr)

            bound = subprocess.run(
                [
                    sys.executable, str(script),
                    "--names-json", str(names_path),
                    "--out", str(output_path),
                    "--functions-json", str(functions_path),
                    "--analysis-json", str(analysis_path),
                    "--xbe", str(xbe_path),
                    "--apply",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(bound.returncode, 0, bound.stderr)
            updated = json.loads(functions_path.read_text(encoding="utf-8"))
            self.assertEqual(updated[0]["name"], "LaylatEntry")
            self.assertTrue(Path(str(functions_path) + ".bak").is_file())

    def test_profile_round_trip_is_deterministic(self) -> None:
        """Writing and loading a profile should preserve target identity."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "laylat-wars.json"
            original = profile_from_analysis(sample_analysis())
            write_target_profile(original, path)
            loaded = load_target_profile(profile_path=path)
        self.assertEqual(loaded.to_dict(), original.to_dict())


if __name__ == "__main__":
    unittest.main()
