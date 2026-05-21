from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scanner.cli import run_scan
from scanner.detector import detect_framework
from scanner.file_loader import collect_files
from scanner.models import ScanReport


class ScannerSmokeTests(unittest.TestCase):
    def test_scan_report_default_framework_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = ScanReport.new(Path(temp_dir))
            data = report.to_dict()
            self.assertEqual(data["framework"], "unknown")
            self.assertEqual(data["findings"], [])
            self.assertEqual(data["scanned_files_count"], 0)

    def test_cli_scan_writes_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "README.md").write_text("# ignored extension\n", encoding="utf-8")
            output_file = root / "report.json"
            exit_code = run_scan(str(root), str(output_file))

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_file.exists())
            data = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(data["framework"], "unknown")
            self.assertEqual(data["scanned_files_count"], 1)

    def test_detector_django_by_manage_py(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "manage.py").write_text("print('manage')\n", encoding="utf-8")
            self.assertEqual(detect_framework(root), "django")

    def test_detector_django_by_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("Django==5.0.0\n", encoding="utf-8")
            self.assertEqual(detect_framework(root), "django")

    def test_detector_express_by_package_json_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(
                '{"dependencies":{"express":"^4.18.0"}}\n',
                encoding="utf-8",
            )
            self.assertEqual(detect_framework(root), "express")

    def test_detector_express_by_server_js_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "server.js").write_text(
                "const app = express();\n",
                encoding="utf-8",
            )
            self.assertEqual(detect_framework(root), "express")

    def test_collect_files_applies_ignores_and_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "main.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "notes.txt").write_text("hello\n", encoding="utf-8")
            (root / "README.md").write_text("ignored\n", encoding="utf-8")

            git_dir = root / ".git"
            git_dir.mkdir(parents=True, exist_ok=True)
            (git_dir / "config").write_text("ignored\n", encoding="utf-8")

            node_modules = root / "node_modules"
            node_modules.mkdir(parents=True, exist_ok=True)
            (node_modules / "lib.js").write_text("ignored\n", encoding="utf-8")

            files = collect_files(root)
            rel_paths = {str(path.relative_to(root)) for path in files}
            self.assertEqual(rel_paths, {"main.py", "notes.txt"})

    def test_module_help_works(self) -> None:
        result = subprocess.run(
            ["python3", "-m", "scanner", "--help"],
            cwd="/Users/charan/Documents/vardhan_thesis_docs/Tool",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("scan", result.stdout)


if __name__ == "__main__":
    unittest.main()
