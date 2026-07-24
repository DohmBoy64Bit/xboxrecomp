"""
CLI entry point for the disassembly tool.

Usage:
    py -3 -m tools.disasm <path_to_xbe> [options]

Examples:
    py -3 -m tools.disasm game_files/default.xbe --analysis-json analysis.json --text-only -v
    py -3 -m tools.disasm game_files/default.xbe --analysis-json analysis.json -o output/
"""

import argparse
import sys

from .disasm import Disassembler


def main():
    """Parse CLI arguments and run target-bound XBE disassembly."""
    parser = argparse.ArgumentParser(
        prog="tools.disasm",
        description="Xbox XBE disassembly tool - static analysis and function detection",
    )

    parser.add_argument(
        "xbe_path",
        help="Path to the Xbox XBE executable file",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_dir",
        required=True,
        help="Target-specific output directory for JSON databases and ASM listings",
    )
    parser.add_argument(
        "--analysis-json",
        required=True,
        help="Path to parser analysis JSON for the exact target XBE",
    )
    parser.add_argument(
        "--target-profile",
        default=None,
        help=(
            "Per-title profile for section roles and annotations. When supplied, it is "
            "cross-checked against the exact analysis JSON and XBE."
        ),
    )
    parser.add_argument(
        "--text-only",
        action="store_true",
        help="Only disassemble the selected target's .text section",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Print statistics only, don't write output files",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output with progress information",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-analysis even if cache is valid",
    )
    parser.add_argument(
        "--extra-sections",
        default=None,
        help="Comma-separated list of additional section names to treat as code "
             "(for sections marked non-executable in the XBE but containing code, "
             "e.g., --extra-sections XIPS,DOLBY)",
    )
    parser.add_argument(
        "--seed-functions",
        default=None,
        help="JSON file with additional function entry points to seed the detector. "
             "Format: array of objects with 'start' field (hex address string). "
             "Use identified_functions.json from func_id to feed back vtable thunks.",
    )

    args = parser.parse_args()

    try:
        extra = [s.strip() for s in args.extra_sections.split(",")] if args.extra_sections else []
        seed_funcs = _load_seed_functions(args.seed_functions) if args.seed_functions else []
        disassembler = Disassembler(
            xbe_path=args.xbe_path,
            analysis_json=args.analysis_json,
            target_profile=args.target_profile,
            output_dir=args.output_dir,
            text_only=args.text_only,
            stats_only=args.stats_only,
            verbose=args.verbose,
            force=args.force,
            extra_sections=extra,
            seed_functions=seed_funcs,
        )
        success = disassembler.run()
        sys.exit(0 if success else 1)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)


def _load_seed_functions(path):
    """Load seed function addresses from a JSON file."""
    import json
    with open(path) as f:
        data = json.load(f)
    addrs = []
    for entry in data:
        if isinstance(entry, dict) and "start" in entry:
            addrs.append(int(entry["start"], 16))
        elif isinstance(entry, int):
            addrs.append(entry)
    return addrs


if __name__ == "__main__":
    main()
