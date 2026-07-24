"""
Main disassembly orchestrator.

Coordinates all analysis passes and produces the final output.
"""

import time
from pathlib import Path
from typing import List, Optional

from tools.target_profile import TargetProfile, load_target_profile

from . import config
from .loader import load_image, BinaryImage, SectionInfo
from .engine import DisasmEngine
from .functions import FunctionDetector
from .xrefs import build_xrefs, XRefTracker
from .labels import (
    LabelManager, populate_kernel_labels, populate_entry_point,
    extract_strings, populate_string_labels,
)
from .output import OutputWriter, print_stats
from .cache import AnalysisCache


class Disassembler:
    """
    Top-level disassembly orchestrator.

    Usage:
        d = Disassembler(
            "path/to/default.xbe",
            analysis_json="analysis/target_analysis.json",
            target_profile="targets/my-game.json",
            output_dir="analysis/disasm",
        )
        d.run()
    """

    def __init__(self, xbe_path: str,
                 analysis_json: Optional[str] = None,
                 target_profile: Optional[str] = None,
                 output_dir: Optional[str] = None,
                 text_only: bool = False,
                 stats_only: bool = False,
                 verbose: bool = False,
                 force: bool = False,
                 extra_sections: Optional[list] = None,
                 seed_functions: Optional[list] = None):
        """Initialize one explicit-target disassembly run and its output state."""
        self.xbe_path = xbe_path
        self.analysis_json = analysis_json
        self.target_profile_path = target_profile
        if not output_dir:
            raise ValueError("Disassembler requires an explicit target-specific output directory")
        self.output_dir = output_dir
        self.text_only = text_only
        self.stats_only = stats_only
        self.verbose = verbose
        self.force = force
        self.extra_sections = extra_sections or []
        self.seed_functions = seed_functions or []

        # Components (initialized during run)
        self.image: Optional[BinaryImage] = None
        self.profile: Optional[TargetProfile] = None
        self.engine: Optional[DisasmEngine] = None
        self.labels: Optional[LabelManager] = None
        self.xrefs: Optional[XRefTracker] = None
        self.func_detector: Optional[FunctionDetector] = None
        self.strings: List[dict] = []

    def run(self) -> bool:
        """
        Execute the full disassembly pipeline.

        Returns True on success.
        """
        t_start = time.time()

        if not self.analysis_json:
            raise ValueError(
                "an explicit parser analysis JSON is required; automatic selection "
                "can mix databases from different targets"
            )
        json_path = self.analysis_json
        self.profile = load_target_profile(
            profile_path=self.target_profile_path,
            analysis_json=json_path,
            xbe_path=self.xbe_path,
        )

        # Check cache
        cache = AnalysisCache(self.output_dir)
        if not self.force:
            if json_path and cache.is_valid(
                    self.xbe_path, json_path, self.text_only,
                    self.extra_sections, self.seed_functions,
                    self.target_profile_path):
                last_time = cache.get_last_run_time()
                print(f"Cache hit - results unchanged (last run: "
                      f"{last_time:.1f}s)")
                if self.stats_only:
                    self._load_and_print_cached_stats()
                return True

        # Phase 1: Load
        if self.verbose:
            print("Phase 1: Loading binary image...")
        self.image = load_image(self.xbe_path, json_path)
        if self.verbose:
            print(f"  Loaded: {self.image.filepath}")
            print(f"  Base: 0x{self.image.base_address:08X}  "
                  f"Entry: 0x{self.image.entry_point:08X}")
            print(f"  Sections: {len(self.image.sections)}  "
                  f"Kernel imports: {len(self.image.kernel_imports)}")

        # Determine sections to analyze
        sections = self._get_target_sections()
        if self.verbose:
            print(f"  Target sections: {', '.join(s.name for s in sections)}")

        # Phase 2: Labels (pre-populate known symbols)
        if self.verbose:
            print("\nPhase 2: Populating labels...")
        self.labels = LabelManager()
        populate_entry_point(self.labels, self.image)
        ki_count = populate_kernel_labels(self.labels, self.image)
        if self.verbose:
            print(f"  Kernel import labels: {ki_count}")

        # Extract strings from .rdata
        self.strings = extract_strings(self.image)
        str_count = populate_string_labels(self.labels, self.strings)
        if self.verbose:
            print(f"  String labels: {str_count}")
            print(f"  Total labels: {self.labels.count()}")

        # Phase 3: Disassembly (linear sweep)
        if self.verbose:
            print("\nPhase 3: Linear sweep disassembly...")
        self.engine = DisasmEngine(self.image)

        total_insns = 0
        for sec in sections:
            if self.verbose:
                print(f"  {sec.name}: 0x{sec.virtual_addr:08X} "
                      f"({sec.virtual_size / 1024:.1f} KB)...", end="", flush=True)

            def progress(done, total):
                if self.verbose:
                    pct = done * 100 // total
                    print(f"\r  {sec.name}: 0x{sec.virtual_addr:08X} "
                          f"({sec.virtual_size / 1024:.1f} KB)... "
                          f"{pct}%", end="", flush=True)

            n = self.engine.linear_sweep(sec, progress_callback=progress)
            total_insns += n
            if self.verbose:
                print(f"\r  {sec.name}: {n:,d} instructions")

        if self.verbose:
            print(f"  Total: {total_insns:,d} instructions")

        # Phase 4: Cross-references
        if self.verbose:
            print("\nPhase 4: Building cross-references...")
        self.xrefs = build_xrefs(self.engine, self.image)
        if self.verbose:
            counts = self.xrefs.count_by_type()
            print(f"  Total xrefs: {self.xrefs.count():,d}")
            for xtype, count in sorted(counts.items()):
                print(f"    {xtype}: {count:,d}")

        # Phase 5: Function detection
        if self.verbose:
            print("\nPhase 5: Detecting functions...")
        self.func_detector = FunctionDetector(
            self.engine, self.image, self.xrefs, self.labels)

        # Add seed functions from vtable scanner or other sources
        if self.seed_functions:
            for addr in self.seed_functions:
                self.func_detector._add_candidate(addr, 0.95, "seed_vtable_thunk")
            if self.verbose:
                print(f"  Seeded {len(self.seed_functions)} function addresses")

        num_funcs = self.func_detector.detect_all(sections)
        if self.verbose:
            summary = self.func_detector.summary()
            print(f"  Total functions: {num_funcs:,d}")
            for method, count in sorted(
                    summary["by_detection_method"].items()):
                print(f"    {method}: {count:,d}")

        # Phase 6: Recursive descent validation
        if self.verbose:
            print("\nPhase 6: Recursive descent validation...")
        start_addrs = [self.image.entry_point]
        start_addrs.extend(self.func_detector.functions.keys())
        section_bounds = [
            (s.virtual_addr, s.virtual_addr + s.virtual_size)
            for s in sections
        ]
        reachable = self.engine.recursive_descent(start_addrs, section_bounds)
        if self.verbose:
            coverage = len(reachable) / total_insns * 100 if total_insns else 0
            print(f"  Reachable instructions: {len(reachable):,d} "
                  f"({coverage:.1f}%)")

        elapsed = time.time() - t_start

        # Print stats
        if self.stats_only or self.verbose:
            print_stats(self.engine, self.func_detector, self.xrefs,
                        self.labels, self.strings, self.image)
            print(f"\n  Elapsed: {elapsed:.2f}s")

        # Phase 7: Output
        if not self.stats_only:
            if self.verbose:
                print(f"\nPhase 7: Writing output to {self.output_dir}/...")
            writer = OutputWriter(
                self.output_dir, self.engine, self.func_detector,
                self.xrefs, self.labels, self.image, self.strings)
            writer.write_all(sections_to_disasm=sections, verbose=self.verbose)

            # Save cache against the explicit target analysis and profile.
            cache.save(
                self.xbe_path, json_path, self.text_only, elapsed,
                self.extra_sections, self.seed_functions,
                self.target_profile_path,
            )

            if self.verbose:
                print(f"\n  Output written to {self.output_dir}/")

        print(f"Done in {elapsed:.2f}s")
        return True

    def _get_target_sections(self) -> List[SectionInfo]:
        """Determine which exact-target sections are approved for disassembly."""
        assert self.image is not None
        if self.text_only:
            text = self.image.get_section(".text")
            if text is None:
                raise ValueError("No .text section found")
            sections = [text]
        elif self.profile is not None:
            sections = []
            for profile_section in self.profile.code_sections:
                section = self.image.get_section(profile_section.name)
                if section is None:
                    raise ValueError(
                        f"Target profile section {profile_section.name!r} is absent from the XBE"
                    )
                if section.raw_size == 0:
                    raise ValueError(
                        f"Target profile marks {profile_section.name!r} as code, "
                        "but the section has no raw bytes"
                    )
                sections.append(section)
        else:
            sections = list(self.image.get_code_sections())

        if self.extra_sections:
            approved = (
                {section.name for section in self.profile.code_sections}
                if self.profile is not None else None
            )
            existing_names = {section.name for section in sections}
            for name in self.extra_sections:
                if name in existing_names:
                    continue
                if approved is not None and name not in approved:
                    raise ValueError(
                        f"Extra section {name!r} is not approved as code by target profile "
                        f"{self.profile.profile_id!r}; update and revalidate the profile"
                    )
                section = self.image.get_section(name)
                if section is None:
                    raise ValueError(f"Extra section {name!r} was not found in the XBE")
                if section.raw_size == 0:
                    raise ValueError(f"Extra section {name!r} has no raw data")
                sections.append(section)

        return sections

    def _load_and_print_cached_stats(self) -> None:
        """Load and print stats from cached summary.json."""
        summary_path = Path(self.output_dir) / "summary.json"
        if not summary_path.exists():
            print("  (no cached summary available)")
            return

        import json
        with open(summary_path) as f:
            summary = json.load(f)

        print(f"\n{'=' * 60}")
        print(f"  Cached Disassembly Summary")
        print(f"{'=' * 60}")
        print(f"  Binary: {summary.get('binary', 'N/A')}")
        print(f"  Instructions: {summary.get('total_instructions', 0):,d}")
        print(f"  Functions: {summary.get('total_functions', 0):,d}")
        print(f"  Cross-references: {summary.get('total_xrefs', 0):,d}")
        print(f"  Labels: {summary.get('total_labels', 0):,d}")
        print(f"  Strings: {summary.get('total_strings', 0):,d}")
        print(f"{'=' * 60}")
