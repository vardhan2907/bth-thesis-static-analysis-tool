"""Tests for stratified sampling validation helper (scanner/validate.py)."""
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from scanner.validate import run_validate, _stratified_sample, _sort_by_severity


def _write_results(path: Path, rows: list[dict]) -> None:
    fieldnames = ["finding_id", "project_name", "rule_id", "rule_name",
                  "category", "severity", "risk_score", "file_path",
                  "line", "snippet", "recommendation"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _make_rows(counts: dict[str, int]) -> list[dict]:
    """Generate synthetic finding rows with given severity counts."""
    rows = []
    i = 0
    for sev, n in counts.items():
        for _ in range(n):
            i += 1
            rows.append({
                "finding_id": f"proj__RULE-{i:03d}__{i}",
                "project_name": "proj",
                "rule_id": f"RULE-{i:03d}",
                "rule_name": "Test rule",
                "category": "test",
                "severity": sev,
                "risk_score": "7.0",
                "file_path": f"src/file{i}.py",
                "line": str(i),
                "snippet": f"code line {i}",
                "recommendation": "Fix it.",
            })
    return rows


class TestRunValidate(unittest.TestCase):

    def test_writes_template_csv(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            results = root / "results.csv"
            _write_results(results, _make_rows({"High": 10, "Critical": 5}))

            out = root / "validation_template.csv"
            count = run_validate(results, out, n=10, seed=42)

            self.assertTrue(out.exists())
            self.assertEqual(count, 10)

    def test_output_has_reviewer_columns(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            results = root / "results.csv"
            _write_results(results, _make_rows({"High": 20}))
            out = root / "template.csv"
            run_validate(results, out, n=5, seed=1)

            with out.open(encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                self.assertIn("reviewer_label", reader.fieldnames or [])
                self.assertIn("notes", reader.fieldnames or [])
                row = next(reader)
                self.assertEqual(row["reviewer_label"], "")
                self.assertEqual(row["notes"], "")

    def test_n_larger_than_population_returns_all(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            results = root / "results.csv"
            _write_results(results, _make_rows({"Low": 3, "Medium": 2}))
            out = root / "template.csv"
            count = run_validate(results, out, n=1000, seed=0)
            self.assertEqual(count, 5)

    def test_missing_results_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            count = run_validate(
                Path(d) / "nonexistent.csv",
                Path(d) / "out.csv",
                n=50,
            )
            self.assertEqual(count, 0)

    def test_sample_respects_seed_reproducibility(self) -> None:
        rows = _make_rows({"Critical": 20, "High": 30, "Medium": 10})
        s1 = _stratified_sample(rows, 20, seed=99)
        s2 = _stratified_sample(rows, 20, seed=99)
        self.assertEqual(
            [r["finding_id"] for r in s1],
            [r["finding_id"] for r in s2],
        )

    def test_different_seeds_give_different_results(self) -> None:
        rows = _make_rows({"High": 50})
        s1 = _stratified_sample(rows, 10, seed=1)
        s2 = _stratified_sample(rows, 10, seed=2)
        # Very likely to differ with 50 items sampled to 10
        self.assertNotEqual(
            [r["finding_id"] for r in s1],
            [r["finding_id"] for r in s2],
        )

    def test_stratified_sample_size_does_not_exceed_n(self) -> None:
        rows = _make_rows({"Critical": 10, "High": 40, "Medium": 30, "Low": 20})
        for n in (10, 25, 50, 99):
            sample = _stratified_sample(rows, n, seed=0)
            self.assertLessEqual(len(sample), n, f"n={n}: got {len(sample)}")

    def test_stratified_sample_includes_all_severities(self) -> None:
        rows = _make_rows({"Critical": 5, "High": 20, "Medium": 15, "Low": 10})
        sample = _stratified_sample(rows, 20, seed=42)
        severities = {r["severity"] for r in sample}
        # All four tiers should be represented in a sample of 20 from 50
        self.assertEqual(severities, {"Critical", "High", "Medium", "Low"})

    def test_output_sorted_critical_first(self) -> None:
        rows = _make_rows({"Low": 5, "Critical": 5, "Medium": 5, "High": 5})
        sorted_rows = _sort_by_severity(rows)
        severities = [r["severity"] for r in sorted_rows]
        # First 5 should be Critical
        self.assertTrue(all(s == "Critical" for s in severities[:5]))
        # Last 5 should be Low
        self.assertTrue(all(s == "Low" for s in severities[-5:]))


if __name__ == "__main__":
    unittest.main()
