"""
Target-profile-driven Xbox x86 → C static recompiler.

Usage:
    py -3 -m tools.recomp <xbe_path> [options]

Options:
    -o, --output-dir DIR    Required target-specific output directory
    -f, --function ADDR     Translate a single function (hex address)
    -c, --category CAT      Translate functions of a specific category
    --game-only             Only translate game_engine + game_vtable + unknown functions
    --all                   Translate all functions (including RW, CRT, XDK)
    -n, --max-funcs N       Maximum number of functions to translate
    -v, --verbose           Verbose output
    --list-categories       List available function categories and counts
    --header                Generate C header with forward declarations
    --split N --gen-dir DIR Generate target-specific split C output
"""

import argparse
import os
import sys
import time

from .translator import BatchTranslator
from .output import write_summary, print_stats, generate_header
from tools.target_profile import TargetProfileError, load_target_profile


def list_categories(translator):
    """Print category breakdown."""
    cats = {}
    for addr, func_info in sorted(translator.func_db.items()):
        cls = translator.classification_db.get(addr, {})
        cat = cls.get("category", "unknown")
        cats[cat] = cats.get(cat, 0) + 1

    print(f"\nFunction categories ({len(translator.func_db)} total):")
    print(f"{'Category':<30} {'Count':>8} {'Pct':>8}")
    print("-" * 48)
    for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
        pct = count / len(translator.func_db) * 100
        print(f"{cat:<30} {count:>8} {pct:>7.1f}%")


def main():
    """Parse CLI arguments and run target-profile-bound recompilation."""
    parser = argparse.ArgumentParser(
        description="Xbox x86 -> C Static Recompiler")
    parser.add_argument("xbe_path", help="Path to default.xbe")
    parser.add_argument(
        "--analysis-json",
        help="Parser analysis JSON for the exact target XBE",
    )
    parser.add_argument(
        "--target-profile",
        help="Per-title profile with section roles and special-function addresses",
    )
    parser.add_argument(
        "--functions", required=True,
        help="Explicit functions.json path for the selected target",
    )
    parser.add_argument("--labels", help="Explicit labels.json path")
    parser.add_argument("--identified", help="Explicit identified_functions.json path")
    parser.add_argument("--abi", help="Explicit abi_functions.json path")
    parser.add_argument(
        "-o", "--output-dir", required=True,
        help="Target-specific output directory for summaries and single-file output",
    )
    parser.add_argument("-f", "--function",
                        help="Translate single function (hex address)")
    parser.add_argument("-c", "--category",
                        help="Translate functions of a category")
    parser.add_argument("--game-only", action="store_true",
                        help="Only game functions (game_engine, game_vtable, unknown)")
    parser.add_argument("--all", action="store_true",
                        help="Translate all functions")
    parser.add_argument("-n", "--max-funcs", type=int,
                        help="Max functions to translate")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--list-categories", action="store_true",
                        help="List categories and exit")
    parser.add_argument("--header", action="store_true",
                        help="Generate C header file")
    parser.add_argument("--split", type=int, metavar="N",
                        help="Split output into files of N functions each")
    parser.add_argument("--gen-dir",
                        help="Required output directory when --split is used")

    args = parser.parse_args()

    try:
        target_profile = load_target_profile(
            profile_path=args.target_profile,
            analysis_json=args.analysis_json,
            xbe_path=args.xbe_path,
        )
    except TargetProfileError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    data_files = {
        "functions": args.functions,
        "labels": args.labels,
        "identified": args.identified,
        "abi": args.abi,
    }
    for key, value in data_files.items():
        if value and not os.path.isfile(value):
            print(f"ERROR: {key} database not found: {value}", file=sys.stderr)
            sys.exit(1)
    if args.split and not args.gen_dir:
        print(
            "ERROR: --split requires an explicit --gen-dir to prevent "
            "cross-target generated output",
            file=sys.stderr,
        )
        sys.exit(2)

    print(
        f"Target profile: {target_profile.profile_id} ({target_profile.title})",
        file=sys.stderr,
    )
    print("Loading data files...", file=sys.stderr)
    t0 = time.time()

    translator = BatchTranslator(
        xbe_path=args.xbe_path,
        func_json_path=data_files["functions"],
        labels_json_path=data_files.get("labels"),
        identified_json_path=data_files.get("identified"),
        abi_json_path=data_files.get("abi"),
        output_dir=args.output_dir,
        target_profile=target_profile,
    )

    t_load = time.time() - t0
    print(f"Loaded {len(translator.func_db)} functions, "
          f"{len(translator.label_db)} labels, "
          f"{len(translator.classification_db)} classifications, "
          f"{len(translator.abi_db)} ABI entries "
          f"in {t_load:.1f}s", file=sys.stderr)

    # List categories mode
    if args.list_categories:
        list_categories(translator)
        return

    # Single function mode
    if args.function:
        addr = int(args.function, 16)
        code = translator.translate_single(addr)
        if code:
            print(code)
        else:
            print(f"ERROR: Could not translate function at 0x{addr:08X}",
                  file=sys.stderr)
            sys.exit(1)
        return

    # Generate header mode
    if args.header:
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)

        if args.game_only:
            funcs = translator.get_functions_by_category(
                categories={"game_engine", "game_vtable", "unknown"})
        elif args.category:
            funcs = translator.get_functions_by_category(
                categories={args.category})
        else:
            funcs = translator.get_functions_by_category()

        header_path = os.path.join(output_dir, "recomp_functions.h")
        generate_header(
            funcs,
            header_path,
            abi_db=translator.abi_db,
            target_name=target_profile.title,
        )
        print(f"Generated header: {header_path} ({len(funcs)} declarations)")
        return

    # Batch translation
    t0 = time.time()

    if args.category:
        categories = {args.category}
        funcs = translator.get_functions_by_category(categories=categories)
    elif args.game_only:
        # Game-specific functions only
        categories = {"game_engine", "game_vtable", "unknown"}
        funcs = translator.get_functions_by_category(categories=categories)
    elif args.all:
        funcs = translator.get_functions_by_category()
    else:
        # Default: game functions only
        categories = {"game_engine", "game_vtable", "unknown"}
        funcs = translator.get_functions_by_category(categories=categories)

    print(f"\nTranslating {len(funcs)} functions...", file=sys.stderr)

    if args.split:
        # Split output mode: multiple .c files + header + dispatch table
        gen_dir = args.gen_dir

        if args.max_funcs:
            funcs = funcs[:args.max_funcs]

        stats = translator.translate_batch_split(
            funcs,
            output_dir=gen_dir,
            chunk_size=args.split,
            verbose=args.verbose,
        )

        t_translate = time.time() - t0
        print(f"\n=== Split Translation Complete ({t_translate:.1f}s) ===",
              file=sys.stderr)
        print(f"{stats['translated']}/{stats['total']} functions "
              f"({stats['failed']} failed), "
              f"{stats['total_lines']} lines of C, "
              f"{stats['num_chunks']} source files",
              file=sys.stderr)
        for f_path in stats.get("files", []):
            print(f"  {f_path}", file=sys.stderr)
    else:
        stats = translator.translate_batch(
            funcs,
            max_funcs=args.max_funcs,
            verbose=args.verbose,
        )

        t_translate = time.time() - t0

        print(f"\n=== Translation Complete ({t_translate:.1f}s) ===",
              file=sys.stderr)
        print_stats(stats)

    # Write summary
    output_dir = args.output_dir
    summary_path = write_summary(stats, output_dir)
    print(f"\nSummary: {summary_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
