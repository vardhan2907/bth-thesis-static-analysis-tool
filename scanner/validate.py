"""Stratified sampling for manual validation of scanner findings.

Reads outputs/results.csv (produced by `batch`), draws a sample stratified
by severity, and writes a validation_template.csv with blank reviewer_label
and notes columns ready for human annotation.

Usage:
    python -m scanner validate \\
        --results outputs/results.csv \\
        --n 100 \\
        --out outputs/validation_template.csv \\
        [--seed 42]
"""
from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

# Severity ordering: highest risk first.
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

_TEMPLATE_FIELDNAMES = [
    "finding_id",
    "project_name",
    "rule_id",
    "rule_name",
    "category",
    "severity",
    "risk_score",
    "file_path",
    "line",
    "snippet",
    "recommendation",
    "reviewer_label",   # TP / FP / Unclear  (filled by reviewer)
    "notes",            # free text           (filled by reviewer)
]


def run_validate(
    results_path: Path,
    out_path: Path,
    n: int = 100,
    seed: int | None = None,
) -> int:
    """Sample findings from results_path, write validation template to out_path.

    Returns the number of rows written.
    """
    rows = _read_results(results_path)
    if not rows:
        print(f"No findings found in {results_path}", file=sys.stderr)
        return 0

    sample = _stratified_sample(rows, n, seed)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_TEMPLATE_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for row in sample:
            row.setdefault("reviewer_label", "")
            row.setdefault("notes", "")
            writer.writerow(row)

    print(
        f"Wrote {len(sample)} sampled findings "
        f"(of {len(rows)} total) to {out_path}"
    )
    return len(sample)


def _read_results(path: Path) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Cannot read results file: {exc}", file=sys.stderr)
        return []
    return [dict(row) for row in csv.DictReader(text.splitlines())]


def _stratified_sample(
    rows: list[dict[str, str]],
    n: int,
    seed: int | None,
) -> list[dict[str, str]]:
    """Return up to n rows, sampled proportionally within each severity tier.

    If n >= len(rows) all rows are returned (sorted by severity).
    """
    if n >= len(rows):
        return _sort_by_severity(rows)

    rng = random.Random(seed)

    # Group by severity
    groups: dict[str, list[dict[str, str]]] = {sev: [] for sev in _SEVERITY_ORDER}
    for row in rows:
        sev = row.get("severity", "Low")
        groups.setdefault(sev, []).append(row)

    total = len(rows)
    sample: list[dict[str, str]] = []

    # Proportional quota per group; guarantee at least 1 from non-empty groups
    quotas: dict[str, int] = {}
    for sev in _SEVERITY_ORDER:
        group = groups[sev]
        if not group:
            quotas[sev] = 0
        else:
            raw = n * len(group) / total
            quotas[sev] = max(1, round(raw))

    # Trim to exactly n if rounding pushed total over
    while sum(quotas.values()) > n:
        # Remove one from the largest-quota group that still has > 1
        biggest = max(
            (sev for sev in _SEVERITY_ORDER if quotas[sev] > 1),
            key=lambda s: quotas[s],
            default=None,
        )
        if biggest is None:
            break
        quotas[biggest] -= 1

    for sev in _SEVERITY_ORDER:
        group = groups[sev]
        quota = min(quotas[sev], len(group))
        sample.extend(rng.sample(group, quota))

    return _sort_by_severity(sample)


def _sort_by_severity(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    order = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}
    return sorted(rows, key=lambda r: order.get(r.get("severity", "Low"), 99))
