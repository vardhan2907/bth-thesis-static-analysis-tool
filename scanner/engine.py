from __future__ import annotations

from pathlib import Path

from .detector import detect_framework
from .file_loader import FileLoader
from .models import ScanReport
from .rules import run_django_rules, run_express_rules


def scan_repository(target: Path) -> ScanReport:
    report = ScanReport.new(target)

    if not target.exists():
        report.errors.append(f"Target path does not exist: {target}")
        return report
    if not target.is_dir():
        report.errors.append(f"Target path is not a directory: {target}")
        return report

    loader = FileLoader(target)

    try:
        report.framework = detect_framework(target)
        report.scanned_files_count = len(loader.list_files())

        if report.framework == "django":
            report.findings.extend(run_django_rules(target, loader))
        elif report.framework == "express":
            report.findings.extend(run_express_rules(target, loader))
    except Exception as exc:  # pragma: no cover - defensive guard
        report.errors.append(f"Unexpected scan error: {exc}")

    return report
