"""
compute_frequency.py — Frequency and distribution analysis for RQ1.

RQ1: Which application-level security misconfigurations occur most frequently
in small-scale open-source web applications, and how are they distributed
across different misconfiguration categories?

Reads the full results.csv (all findings, not just the validation sample).

Usage:
    python3 compute_frequency.py
    python3 compute_frequency.py --csv outputs/results.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict


def load_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def sep(char="─", w=72):
    print(char * w)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="outputs/results.csv")
    args = parser.parse_args()

    rows = load_csv(args.csv)

    # Skip header-like rows or empty
    rows = [r for r in rows if r.get("rule_id", "").strip().startswith(("DJ-", "EX-"))]

    total_findings = len(rows)
    all_projects   = {r["project_name"] for r in rows}
    total_projects = len(all_projects)

    W = 72
    print()
    sep("═", W)
    print("  MISCONFIGURATION FREQUENCY & DISTRIBUTION  (RQ1)")
    sep("═", W)
    print(f"  Total findings : {total_findings}")
    print(f"  Projects with findings : {total_projects}")

    # ── 1. Frequency by rule ──────────────────────────────────────────────────
    rule_findings  = defaultdict(int)   # finding count
    rule_projects  = defaultdict(set)   # unique projects per rule
    rule_meta      = {}                 # name + category + framework

    for r in rows:
        rid  = r["rule_id"]
        proj = r["project_name"]
        rule_findings[rid] += 1
        rule_projects[rid].add(proj)
        if rid not in rule_meta:
            fw = "Django" if rid.startswith("DJ") else "Express"
            rule_meta[rid] = {
                "name": r.get("rule_name", rid),
                "category": r.get("category", ""),
                "framework": fw,
            }

    print()
    print("FREQUENCY BY RULE  (sorted by finding count)")
    sep()
    print(f"  {'Rule':<18} {'Name':<36} {'Findings':>8} {'Projects':>9} {'Prev%':>7}")
    sep("-", W)
    for rid, count in sorted(rule_findings.items(), key=lambda x: -x[1]):
        meta  = rule_meta[rid]
        projs = len(rule_projects[rid])
        prev  = projs / total_projects * 100
        name  = meta["name"][:34]
        print(f"  {rid:<18} {name:<36} {count:>8} {projs:>9} {prev:>6.1f}%")

    # ── 2. Distribution by category ───────────────────────────────────────────
    cat_findings  = defaultdict(int)
    cat_projects  = defaultdict(set)

    for r in rows:
        cat  = r.get("category", "unknown")
        proj = r["project_name"]
        cat_findings[cat] += 1
        cat_projects[cat].add(proj)

    print()
    print("DISTRIBUTION BY CATEGORY")
    sep()
    print(f"  {'Category':<30} {'Findings':>8} {'% of total':>11} {'Projects':>9}")
    sep("-", W)
    for cat, count in sorted(cat_findings.items(), key=lambda x: -x[1]):
        pct   = count / total_findings * 100
        projs = len(cat_projects[cat])
        print(f"  {cat:<30} {count:>8} {pct:>10.1f}% {projs:>9}")

    # ── 3. Django vs Express breakdown ────────────────────────────────────────
    fw_findings  = defaultdict(int)
    fw_projects  = defaultdict(set)
    fw_rules     = defaultdict(set)

    for r in rows:
        fw   = r.get("framework", "").strip().lower()
        if not fw:
            fw = "django" if r["rule_id"].startswith("DJ") else "express"
        proj = r["project_name"]
        fw_findings[fw] += 1
        fw_projects[fw].add(proj)
        fw_rules[fw].add(r["rule_id"])

    print()
    print("DJANGO vs EXPRESS BREAKDOWN")
    sep()
    print(f"  {'Framework':<12} {'Findings':>8} {'% of total':>11} {'Projects':>9} {'Avg/project':>12}")
    sep("-", W)
    for fw in ["django", "express"]:
        count = fw_findings[fw]
        projs = len(fw_projects[fw])
        pct   = count / total_findings * 100
        avg   = count / projs if projs else 0
        print(f"  {fw.title():<12} {count:>8} {pct:>10.1f}% {projs:>9} {avg:>11.1f}")

    # ── 4. Prevalence: how many projects affected per rule ────────────────────
    print()
    print("PREVALENCE RATE  (% of all scanned projects with at least 1 finding of this rule)")
    print(f"  (denominator = {total_projects} projects that produced findings)")
    sep()

    # Django rules — denominator = Django projects with findings
    django_projects = {r["project_name"] for r in rows if r["rule_id"].startswith("DJ")}
    express_projects = {r["project_name"] for r in rows if r["rule_id"].startswith("EX")}

    print(f"  Django rules  (base: {len(django_projects)} Django projects with findings)")
    sep("-", W)
    for rid, count in sorted(
        ((r, c) for r, c in rule_findings.items() if r.startswith("DJ")),
        key=lambda x: -len(rule_projects[x[0]])
    ):
        projs = len(rule_projects[rid])
        prev  = projs / len(django_projects) * 100
        name  = rule_meta[rid]["name"][:34]
        print(f"  {rid:<18} {name:<34} {projs:>3}/{len(django_projects)} projects  ({prev:.0f}%)")

    print()
    print(f"  Express rules  (base: {len(express_projects)} Express projects with findings)")
    sep("-", W)
    for rid, count in sorted(
        ((r, c) for r, c in rule_findings.items() if r.startswith("EX")),
        key=lambda x: -len(rule_projects[x[0]])
    ):
        projs = len(rule_projects[rid])
        prev  = projs / len(express_projects) * 100
        name  = rule_meta[rid]["name"][:34]
        print(f"  {rid:<18} {name:<34} {projs:>3}/{len(express_projects)} projects  ({prev:.0f}%)")

    # ── 5. Per-project finding count (top 10) ─────────────────────────────────
    proj_counts = defaultdict(int)
    proj_fw     = {}
    for r in rows:
        proj_counts[r["project_name"]] += 1
        fw = "Django" if r["rule_id"].startswith("DJ") else "Express"
        proj_fw[r["project_name"]] = fw

    print()
    print("TOP 10 PROJECTS BY FINDING COUNT")
    sep()
    print(f"  {'Project':<36} {'Framework':<10} {'Findings':>8}")
    sep("-", W)
    for proj, count in sorted(proj_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {proj:<36} {proj_fw[proj]:<10} {count:>8}")

    print()
    sep("═", W)
    print()


if __name__ == "__main__":
    main()
