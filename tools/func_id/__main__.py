"""
CLI entry point for the function identification tool.

Usage:
    py -3 -m tools.func_id default.xbe --analysis-json analysis.json [-v]
    py -3 -m tools.func_id default.xbe --target-profile targets/game.json [-v]
"""

import argparse
import sys

from .identify import run


def main():
    """Parse CLI arguments and run function identification for one target."""
    parser = argparse.ArgumentParser(
        description="Identify CRT, middleware, library, and game functions in an Xbox XBE"
    )
    parser.add_argument(
        "xbe_path",
        help="Path to default.xbe"
    )
    parser.add_argument(
        "--analysis-json",
        help="Parser analysis JSON for the exact target XBE",
    )
    parser.add_argument(
        "--target-profile",
        help="Per-title profile with section roles and special annotations",
    )
    parser.add_argument(
        "--functions",
        required=True,
        help="Path to this target's functions.json"
    )
    parser.add_argument(
        "--strings",
        required=True,
        help="Path to this target's strings.json"
    )
    parser.add_argument(
        "--xrefs",
        required=True,
        help="Path to this target's xrefs.json"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Target-specific output directory"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress"
    )

    args = parser.parse_args()

    try:
        summary = run(
            xbe_path=args.xbe_path,
            functions_path=args.functions,
            strings_path=args.strings,
            xrefs_path=args.xrefs,
            output_dir=args.output,
            verbose=args.verbose,
            analysis_json=args.analysis_json,
            target_profile=args.target_profile,
        )
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
