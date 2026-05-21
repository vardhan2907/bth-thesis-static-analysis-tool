"""
run_baseline.py — Run Bandit, Semgrep, and njsscan on all dataset repos.

Produces JSON output files under outputs/baseline/<tool>/<repo_id>.json.

Usage:
    python3 run_baseline.py
    python3 run_baseline.py --data data/data.csv --datadir /path/to/data --out outputs/baseline
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from pathlib import Path


DATA_DIR_DEFAULT = Path(__file__).parent.parent / "data"


def load_repos(csv_path: str, data_dir: Path) -> list[dict]:
    repos = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or not row[0].strip():
                continue
            repo_id = row[0].strip()
            if not (repo_id.startswith("DJ") or repo_id.startswith("EX")):
                continue
            framework_raw = row[3].strip() if len(row) > 3 else ""
            framework = "django" if "django" in framework_raw.lower() else "express"
            path = data_dir / repo_id
            if not path.exists():
                print(f"  [SKIP] {repo_id}: path not found ({path})")
                continue
            repos.append({"id": repo_id, "framework": framework, "path": str(path)})
    return repos


def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def write_json(out_path: Path, data: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def run_bandit(repo: dict, out_dir: Path) -> None:
    repo_id = repo["id"]
    out_path = out_dir / "bandit" / f"{repo_id}.json"
    if out_path.exists():
        print(f"  [SKIP-EXISTS] {repo_id} bandit")
        return
    print(f"  [BANDIT] {repo_id} ...", end=" ", flush=True)
    rc, stdout, stderr = run_cmd(
        ["bandit", "-r", repo["path"], "-f", "json", "-ll"],
        timeout=120,
    )
    # bandit exits with 1 when issues found — that's normal
    if stdout.strip().startswith("{"):
        try:
            data = json.loads(stdout)
            write_json(out_path, data)
            n = len(data.get("results", []))
            print(f"OK ({n} findings)")
        except json.JSONDecodeError:
            write_json(out_path, {"error": "json_parse_error", "stdout": stdout[:500]})
            print("JSON parse error")
    else:
        write_json(out_path, {"error": stderr[:500] or "no_output"})
        print(f"ERROR: {stderr[:80]}")


def run_semgrep(repo: dict, out_dir: Path) -> None:
    repo_id = repo["id"]
    framework = repo["framework"]
    ruleset = "p/django" if framework == "django" else "p/nodejs"
    out_path = out_dir / "semgrep" / f"{repo_id}.json"
    if out_path.exists():
        print(f"  [SKIP-EXISTS] {repo_id} semgrep")
        return
    print(f"  [SEMGREP] {repo_id} ({ruleset}) ...", end=" ", flush=True)
    rc, stdout, stderr = run_cmd(
        [
            "semgrep",
            "--config", ruleset,
            repo["path"],
            "--json",
            "--no-git-ignore",
            "--quiet",
        ],
        timeout=180,
    )
    # semgrep exits 0 (no findings) or 1 (findings found) or other codes for errors
    if stdout.strip().startswith("{"):
        try:
            data = json.loads(stdout)
            write_json(out_path, data)
            n = len(data.get("results", []))
            print(f"OK ({n} findings)")
        except json.JSONDecodeError:
            write_json(out_path, {"error": "json_parse_error", "stdout": stdout[:500]})
            print("JSON parse error")
    else:
        write_json(out_path, {"error": stderr[:500] or stdout[:500] or "no_output"})
        print(f"ERROR: {(stderr or stdout)[:80]}")


def run_njsscan(repo: dict, out_dir: Path) -> None:
    repo_id = repo["id"]
    out_path = out_dir / "njsscan" / f"{repo_id}.json"
    if out_path.exists():
        print(f"  [SKIP-EXISTS] {repo_id} njsscan")
        return
    print(f"  [NJSSCAN] {repo_id} ...", end=" ", flush=True)
    rc, stdout, stderr = run_cmd(
        ["njsscan", "--json", repo["path"]],
        timeout=120,
    )
    if stdout.strip().startswith("{"):
        try:
            data = json.loads(stdout)
            write_json(out_path, data)
            # count findings across all rule keys
            n = sum(
                len(v.get("files", []))
                for v in data.get("nodejs", {}).values()
            )
            print(f"OK ({n} findings)")
        except json.JSONDecodeError:
            write_json(out_path, {"error": "json_parse_error", "stdout": stdout[:500]})
            print("JSON parse error")
    else:
        write_json(out_path, {"error": stderr[:500] or stdout[:500] or "no_output"})
        print(f"ERROR: {(stderr or stdout)[:80]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/data.csv")
    parser.add_argument("--datadir", default=str(DATA_DIR_DEFAULT))
    parser.add_argument("--out", default="outputs/baseline")
    args = parser.parse_args()

    data_dir = Path(args.datadir)
    out_dir = Path(args.out)
    repos = load_repos(args.data, data_dir)

    print(f"\nLoaded {len(repos)} repos from {args.data}")
    print(f"Output directory: {out_dir}\n")

    django_repos = [r for r in repos if r["framework"] == "django"]
    express_repos = [r for r in repos if r["framework"] == "express"]

    print(f"=== Bandit (Django repos only: {len(django_repos)}) ===")
    for repo in django_repos:
        run_bandit(repo, out_dir)

    print(f"\n=== Semgrep (all {len(repos)} repos) ===")
    for repo in repos:
        run_semgrep(repo, out_dir)

    print(f"\n=== njsscan (Express repos only: {len(express_repos)}) ===")
    for repo in express_repos:
        run_njsscan(repo, out_dir)

    print("\nDone. Results in:", out_dir)


if __name__ == "__main__":
    main()
