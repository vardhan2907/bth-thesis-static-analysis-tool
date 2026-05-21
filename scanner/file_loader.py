from __future__ import annotations

from pathlib import Path

IGNORED_DIR_NAMES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    ".next",
    "__pycache__",
}

ALLOWED_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".json",
    ".txt",
    ".env",
    ".example",
}


def collect_files(root_path: str | Path) -> list[Path]:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return []

    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() in ALLOWED_SUFFIXES:
            files.append(path)
    return sorted(files)


def read_text(path: str | Path) -> str:
    file_path = Path(path)
    try:
        data = file_path.read_bytes()
    except OSError:
        return ""

    # UTF-8 first, then safe fallback with replacement so decoding never crashes.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


class FileLoader:
    """Thin stateful wrapper around collect_files / read_text for a given root."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._files: list[Path] | None = None

    def list_files(self) -> list[Path]:
        if self._files is None:
            self._files = collect_files(self._root)
        return self._files

    def read_text(self, path: Path) -> str:
        return read_text(path)
