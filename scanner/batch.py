"""Batch scanning: read a projects CSV, scan each repo, write per-project JSON
and an aggregated results.csv (one row per finding).

Input CSV columns:
    path          - absolute or relative path to the cloned repository (required)
    project_name  - display name for the project (optional; falls back to dir name)

Output:
    <output_dir>/<project_name>/report.json  - full JSON report per project
    <output_dir>/results.csv                 - one row per finding across all projects
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

from .engine import scan_repository

_CSV_FIELDNAMES = [
    "finding_id",
    "project_name",
    "framework",
    "rule_id",
    "rule_name",
    "category",
    "severity",
    "risk_score",
    "file_path",
    "line",
    "snippet",
    "recommendation",
]


def run_batch(
    csv_path: Path,
    output_dir: Path,
    pretty: bool = False,
) -> tuple[int, int]:
    """Scan every project listed in csv_path.

    Returns (projects_scanned, total_findings).
    Prints progress to stdout and errors to stderr.
    """
    rows = _read_projects_csv(csv_path)
    if not rows:
        print(f"No projects found in {csv_path}", file=sys.stderr)
        return 0, 0

    output_dir.mkdir(parents=True, exist_ok=True)

    all_csv_rows: list[dict[str, Any]] = []
    finding_counter = 0
    projects_scanned = 0

    for row in rows:
        path_str = row.get("path", "").strip()
        if not path_str:
            continue

        repo_path = Path(path_str)
        if not repo_path.is_absolute():
            repo_path = csv_path.parent / repo_path

        project_name = row.get("project_name", "").strip() or repo_path.name

        print(f"Scanning {project_name} ({repo_path}) ...", flush=True)

        report = scan_repository(repo_path)
        report.project_name = project_name  # use name from CSV

        if report.errors:
            for err in report.errors:
                print(f"  WARNING: {err}", file=sys.stderr)

        # Save per-project JSON report
        project_out = output_dir / project_name
        project_out.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(report.to_dict(), indent=2 if pretty else None)
        (project_out / "report.json").write_text(payload, encoding="utf-8")

        # Collect rows for results.csv
        for finding in report.findings:
            finding_counter += 1
            all_csv_rows.append({
                "finding_id": f"{project_name}__{finding.rule_id}__{finding_counter}",
                "project_name": project_name,
                "framework": report.framework,
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "category": finding.category,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "file_path": finding.evidence.file_path,
                "line": finding.evidence.line if finding.evidence.line is not None else "",
                "snippet": finding.evidence.snippet or "",
                "recommendation": finding.recommendation,
            })

        n = len(report.findings)
        print(
            f"  {n} finding{'s' if n != 1 else ''} (framework: {report.framework})")
        projects_scanned += 1

    # Write aggregated results.csv
    results_csv = output_dir / "results.csv"
    with results_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_csv_rows)

    total = len(all_csv_rows)
    print(
        f"\nBatch complete: {projects_scanned} project(s) scanned, "
        f"{total} total finding(s)."
    )
    print(f"Results CSV: {results_csv}")
    return projects_scanned, total


def _read_projects_csv(csv_path: Path) -> list[dict[str, str]]:
    try:
        text = csv_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Cannot read CSV: {exc}", file=sys.stderr)
        return []

    reader = csv.DictReader(text.splitlines())
    return [dict(row) for row in reader]
