from __future__ import annotations

import json
from pathlib import Path

from .file_loader import collect_files, read_text


def detect_framework(root_path: str | Path) -> str:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return "unknown"

    files = collect_files(root)

    if _is_django(root, files):
        return "django"
    if _is_express(root):
        return "express"
    return "unknown"


def _is_django(root: Path, files: list[Path]) -> bool:
    if (root / "manage.py").exists():
        return True

    settings_candidates = [
        root / "settings.py",
        root / "config" / "settings.py",
        root / "project" / "settings.py",
    ]
    if any(path.exists() for path in settings_candidates):
        return True

    requirements_path = root / "requirements.txt"
    if requirements_path.exists():
        if "django" in read_text(requirements_path).lower():
            return True

    for path in files:
        if path.name == "settings.py":
            return True
    return False


def _is_express(root: Path) -> bool:
    package_json = root / "package.json"
    if package_json.exists():
        package_data = _safe_load_json(read_text(package_json))
        dependencies = package_data.get("dependencies", {})
        if isinstance(dependencies, dict) and "express" in dependencies:
            return True

    for entry_name in ("app.js", "server.js"):
        entry_path = root / entry_name
        if entry_path.exists() and entry_path.is_file():
            text = read_text(entry_path).lower()
            if "express(" in text:
                return True
    return False


def _safe_load_json(value: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}
