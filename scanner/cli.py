from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .batch import run_batch
from .engine import scan_repository
from .validate import run_validate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Static misconfiguration risk scanner for local repositories.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan a single local repository.")
    scan_parser.add_argument("path", help="Path to repository folder.")
    scan_parser.add_argument(
        "--out",
        default=None,
        help="Output JSON file path. If omitted, JSON is printed to stdout.",
    )
    scan_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )

    # ── batch ─────────────────────────────────────────────────────────────────
    batch_parser = subparsers.add_parser(
        "batch",
        help="Scan multiple repositories listed in a CSV file.",
    )
    batch_parser.add_argument(
        "--csv",
        required=True,
        metavar="FILE",
        help="Path to projects CSV (columns: path, project_name).",
    )
    batch_parser.add_argument(
        "--out",
        default="outputs",
        metavar="DIR",
        help="Output directory for per-project JSON and results.csv (default: outputs/).",
    )
    batch_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print per-project JSON reports.",
    )

    # ── validate ──────────────────────────────────────────────────────────────
    val_parser = subparsers.add_parser(
        "validate",
        help="Sample findings from results.csv for manual validation.",
    )
    val_parser.add_argument(
        "--results",
        default="outputs/results.csv",
        metavar="FILE",
        help="Path to results.csv produced by batch (default: outputs/results.csv).",
    )
    val_parser.add_argument(
        "--n",
        type=int,
        default=100,
        metavar="N",
        help="Number of findings to sample (default: 100).",
    )
    val_parser.add_argument(
        "--out",
        default="outputs/validation_template.csv",
        metavar="FILE",
        help="Output path for the validation template CSV (default: outputs/validation_template.csv).",
    )
    val_parser.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="INT",
        help="Random seed for reproducible sampling (default: random).",
    )

    return parser


def run_scan(path: str, out_path: str | None = None, pretty: bool = False) -> int:
    report = scan_repository(Path(path))
    payload = json.dumps(report.to_dict(), indent=2 if pretty else None)

    if out_path:
        out_file = Path(out_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(payload, encoding="utf-8")
    else:
        print(payload)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args.path, args.out, args.pretty)

    if args.command == "batch":
        run_batch(
            csv_path=Path(args.csv),
            output_dir=Path(args.out),
            pretty=args.pretty,
        )
        return 0

    if args.command == "validate":
        run_validate(
            results_path=Path(args.results),
            out_path=Path(args.out),
            n=args.n,
            seed=args.seed,
        )
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
