"""Tests for batch scanning (scanner/batch.py)."""
from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from scanner.batch import run_batch


def _write(root: Path, name: str, content: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestRunBatch(unittest.TestCase):

    def test_empty_csv_returns_zeros(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            csv_path = root / "projects.csv"
            csv_path.write_text("path,project_name\n", encoding="utf-8")
            out_dir = root / "outputs"
            projects, findings = run_batch(csv_path, out_dir)
        self.assertEqual(projects, 0)
        self.assertEqual(findings, 0)

    def test_missing_csv_returns_zeros(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            projects, findings = run_batch(
                Path(d) / "nonexistent.csv",
                Path(d) / "outputs",
            )
        self.assertEqual(projects, 0)
        self.assertEqual(findings, 0)

    def test_per_project_json_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)

            # Create a minimal Django project
            proj = root / "django_proj"
            _write(proj, "manage.py", "")
            _write(proj, "app/settings.py", "DEBUG = True\n")

            csv_path = root / "projects.csv"
            csv_path.write_text(
                f"path,project_name\n{proj},my-django\n", encoding="utf-8"
            )

            out_dir = root / "outputs"
            run_batch(csv_path, out_dir)

            report_file = out_dir / "my-django" / "report.json"
            self.assertTrue(report_file.exists(), "per-project report.json missing")
            data = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(data["project_name"], "my-django")
            self.assertEqual(data["framework"], "django")

    def test_results_csv_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)

            proj = root / "express_proj"
            _write(proj, "package.json", '{"dependencies":{"express":"^4"}}')
            _write(proj, "app.js", "const app = require('express')();\n")

            csv_path = root / "projects.csv"
            csv_path.write_text(
                f"path,project_name\n{proj},my-express\n", encoding="utf-8"
            )

            out_dir = root / "outputs"
            run_batch(csv_path, out_dir)

            results_csv = out_dir / "results.csv"
            self.assertTrue(results_csv.exists(), "results.csv missing")

            with results_csv.open(encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))

            # At minimum EX-HELMET-001 and EX-JSON-001 should fire
            rule_ids = {row["rule_id"] for row in rows}
            self.assertIn("EX-HELMET-001", rule_ids)
            self.assertEqual(rows[0]["project_name"], "my-express")

    def test_results_csv_has_correct_columns(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)

            proj = root / "proj"
            _write(proj, "manage.py", "")
            _write(proj, "settings.py", "DEBUG = True\n")

            csv_path = root / "projects.csv"
            csv_path.write_text(
                f"path,project_name\n{proj},proj\n", encoding="utf-8"
            )

            out_dir = root / "outputs"
            run_batch(csv_path, out_dir)

            with (out_dir / "results.csv").open(encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                expected = {
                    "finding_id", "project_name", "framework",
                    "rule_id", "rule_name", "category",
                    "severity", "risk_score", "file_path",
                    "line", "snippet", "recommendation",
                }
                self.assertEqual(set(reader.fieldnames or []), expected)

    def test_multiple_projects_aggregated(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)

            dj = root / "dj"
            _write(dj, "manage.py", "")
            _write(dj, "settings.py", "DEBUG = True\n")

            ex = root / "ex"
            _write(ex, "package.json", '{"dependencies":{"express":"^4"}}')
            _write(ex, "app.js", "app.use(express.json());\n")

            csv_path = root / "projects.csv"
            csv_path.write_text(
                f"path,project_name\n{dj},django-proj\n{ex},express-proj\n",
                encoding="utf-8",
            )

            out_dir = root / "outputs"
            projects, total = run_batch(csv_path, out_dir)

            self.assertEqual(projects, 2)
            self.assertGreater(total, 0)

            # Both per-project JSONs exist
            self.assertTrue((out_dir / "django-proj" / "report.json").exists())
            self.assertTrue((out_dir / "express-proj" / "report.json").exists())

            # results.csv contains rows from both projects
            with (out_dir / "results.csv").open(encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            project_names = {row["project_name"] for row in rows}
            self.assertIn("django-proj", project_names)
            self.assertIn("express-proj", project_names)

    def test_project_name_falls_back_to_dir_name(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)

            proj = root / "my_repo_dir"
            _write(proj, "manage.py", "")
            _write(proj, "settings.py", "")

            # CSV has no project_name column
            csv_path = root / "projects.csv"
            csv_path.write_text(f"path\n{proj}\n", encoding="utf-8")

            out_dir = root / "outputs"
            run_batch(csv_path, out_dir)

            # Should use directory name as project name
            self.assertTrue((out_dir / "my_repo_dir" / "report.json").exists())

    def test_nonexistent_repo_path_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)

            csv_path = root / "projects.csv"
            csv_path.write_text(
                "path,project_name\n/nonexistent/path/xyz,bad-proj\n",
                encoding="utf-8",
            )

            out_dir = root / "outputs"
            projects, total = run_batch(csv_path, out_dir)

            # Project is counted as scanned (report saved with errors)
            self.assertEqual(projects, 1)
            self.assertEqual(total, 0)  # no findings from a missing repo

            report_file = out_dir / "bad-proj" / "report.json"
            self.assertTrue(report_file.exists())
            data = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertTrue(len(data["errors"]) > 0)


if __name__ == "__main__":
    unittest.main()
