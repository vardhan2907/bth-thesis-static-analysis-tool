"""
compute_ranking.py — Evaluate how well risk_score prioritises true positives.

Answers RQ: How well does the risk scoring model prioritise detected
misconfigurations compared to an unranked list?

Metrics:
  - Precision@K      : % of top-K ranked findings that are TP (K=10,20,30,50)
  - Average Precision: area under the precision-recall curve for ranked list
  - Random baseline  : expected Precision@K and AP under random ordering
  - Precision by tier: TP rate within each severity tier (Critical / High)

Usage:
    python3 compute_ranking.py
    python3 compute_ranking.py --csv outputs/validation_template.csv --seeds 10000
"""

from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def is_tp(row: dict) -> bool:
    """TP and TP-TEST both count as true positives for ranking purposes."""
    return row["reviewer_label"].strip().upper() in ("TP", "TP-TEST")


def is_scoreable(row: dict) -> bool:
    """Only include rows that have been labeled (skip blanks)."""
    return bool(row.get("reviewer_label", "").strip())


# ── Core metrics ──────────────────────────────────────────────────────────────

def precision_at_k(ranked: list[dict], k: int) -> float:
    top = ranked[:k]
    if not top:
        return 0.0
    return sum(1 for r in top if is_tp(r)) / len(top)


def average_precision(ranked: list[dict]) -> float:
    """
    AP = (1 / R) * sum over positions where finding is TP of P@position
    R = total number of TPs in the list.
    """
    total_tp = sum(1 for r in ranked if is_tp(r))
    if total_tp == 0:
        return 0.0
    running_tp = 0
    ap = 0.0
    for i, row in enumerate(ranked, start=1):
        if is_tp(row):
            running_tp += 1
            ap += running_tp / i
    return ap / total_tp


def random_baseline_ap(n: int, n_tp: int, n_seeds: int = 10000, seed: int = 42) -> float:
    """Monte Carlo estimate of AP under random ordering."""
    rng = random.Random(seed)
    items = [1] * n_tp + [0] * (n - n_tp)
    total = 0.0
    for _ in range(n_seeds):
        rng.shuffle(items)
        total += average_precision_binary(items)
    return total / n_seeds


def average_precision_binary(binary: list[int]) -> float:
    total_tp = sum(binary)
    if total_tp == 0:
        return 0.0
    running_tp = 0
    ap = 0.0
    for i, rel in enumerate(binary, start=1):
        if rel:
            running_tp += 1
            ap += running_tp / i
    return ap / total_tp


def random_baseline_pk(n: int, n_tp: int, k: int, n_seeds: int = 10000, seed: int = 42) -> float:
    """Monte Carlo estimate of Precision@K under random ordering."""
    rng = random.Random(seed)
    items = [1] * n_tp + [0] * (n - n_tp)
    total = 0.0
    for _ in range(n_seeds):
        rng.shuffle(items)
        total += sum(items[:k]) / k
    return total / n_seeds


# ── Precision by severity tier ────────────────────────────────────────────────

def precision_by_tier(rows: list[dict]) -> dict[str, dict]:
    tiers: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "tp_test": 0})
    for r in rows:
        label = r["reviewer_label"].strip().upper()
        sev = r.get("severity", "Unknown").strip()
        if label == "TP":
            tiers[sev]["tp"] += 1
        elif label == "FP":
            tiers[sev]["fp"] += 1
        elif label == "TP-TEST":
            tiers[sev]["tp_test"] += 1
    return dict(tiers)


# ── Precision by risk score band ─────────────────────────────────────────────

def precision_by_score_band(rows: list[dict]) -> dict[str, dict]:
    bands: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "tp_test": 0, "label": ""})
    band_labels = {
        "8.0":       "8.0  (Critical — DJ-DEBUG, DJ-SECRET)",
        "7.5":       "7.5  (High    — EX-AUTHZ)",
        "7.0":       "7.0  (High    — DJ-CSRF, EX-HELMET, EX-RATE)",
        "6.5":       "6.5  (High    — DJ-HOSTS, DJ-COOKIE, EX-JSON, EX-COOKIE)",
        "6.0":       "6.0  (High    — DJ-ERROR)",
    }
    for r in rows:
        try:
            score = f"{float(r.get('risk_score', 0)):.1f}"
        except ValueError:
            score = "?"
        label = r["reviewer_label"].strip().upper()
        bands[score]["label"] = band_labels.get(score, score)
        if label == "TP":
            bands[score]["tp"] += 1
        elif label == "FP":
            bands[score]["fp"] += 1
        elif label == "TP-TEST":
            bands[score]["tp_test"] += 1
    return dict(bands)


# ── Print helpers ─────────────────────────────────────────────────────────────

def sep(char="─", w=72):
    print(char * w)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="outputs/validation_template.csv")
    parser.add_argument("--seeds", type=int, default=10000,
                        help="Monte Carlo iterations for random baseline")
    args = parser.parse_args()

    rows = [r for r in load_csv(args.csv) if is_scoreable(r)]

    # Sort ranked list by risk_score descending (ties broken by finding_id for stability)
    ranked = sorted(rows, key=lambda r: (-float(r.get("risk_score", 0)), r["finding_id"]))

    n      = len(rows)
    n_tp   = sum(1 for r in rows if is_tp(r))   # TP + TP-TEST
    n_fp   = sum(1 for r in rows if r["reviewer_label"].strip().upper() == "FP")

    W = 72
    print()
    sep("═", W)
    print("  RANKING EVALUATION  —  Risk Score vs Unranked Baseline")
    sep("═", W)
    print(f"  Total labeled findings : {n}")
    print(f"  True Positives (TP+TP-TEST) : {n_tp}   False Positives : {n_fp}")

    # ── Precision@K ───────────────────────────────────────────────────────────
    print()
    print("PRECISION@K")
    sep()
    print(f"  {'K':>4}  {'Ranked (risk_score↓)':>22}  {'Random baseline':>18}  {'Δ':>8}")
    sep("-", W)
    for k in [10, 20, 30, 50, n]:
        pk_ranked = precision_at_k(ranked, k)
        pk_random = random_baseline_pk(n, n_tp, k, args.seeds)
        delta = pk_ranked - pk_random
        label = f"(all {n})" if k == n else ""
        print(f"  {k:>4}  {pk_ranked*100:>20.1f}%  {pk_random*100:>16.1f}%  {delta*100:>+7.1f}%  {label}")

    # ── Average Precision ─────────────────────────────────────────────────────
    print()
    print("AVERAGE PRECISION (AP)")
    sep()
    ap_ranked = average_precision(ranked)
    ap_random = random_baseline_ap(n, n_tp, args.seeds)
    print(f"  Ranked (risk_score↓)  :  AP = {ap_ranked:.4f}  ({ap_ranked*100:.1f}%)")
    print(f"  Random baseline       :  AP = {ap_random:.4f}  ({ap_random*100:.1f}%)")
    print(f"  Improvement           :  Δ  = {(ap_ranked - ap_random)*100:+.1f} percentage points")

    # ── Precision by severity tier ────────────────────────────────────────────
    print()
    print("PRECISION BY SEVERITY TIER  (do higher-scored tiers have fewer FPs?)")
    sep()
    print(f"  {'Severity':<12} {'TP':>5} {'FP':>5} {'TP-TEST':>8} {'Precision':>11}")
    sep("-", W)
    tier_data = precision_by_tier(rows)
    for tier in ["Critical", "High", "Medium", "Low"]:
        if tier not in tier_data:
            continue
        c = tier_data[tier]
        denom = c["tp"] + c["fp"]
        prec = c["tp"] / denom if denom else float("nan")
        prec_s = f"{prec*100:.1f}%" if denom else "n/a"
        print(f"  {tier:<12} {c['tp']:>5} {c['fp']:>5} {c['tp_test']:>8} {prec_s:>11}")

    # ── Precision by risk score band ──────────────────────────────────────────
    print()
    print("PRECISION BY RISK SCORE  (finer-grained view)")
    sep()
    print(f"  {'Score / Rule group':<46} {'TP':>4} {'FP':>4} {'TP-TEST':>8} {'Precision':>10}")
    sep("-", W)
    band_data = precision_by_score_band(rows)
    for score in sorted(band_data.keys(), reverse=True):
        c = band_data[score]
        denom = c["tp"] + c["fp"]
        prec = c["tp"] / denom if denom else float("nan")
        prec_s = f"{prec*100:.1f}%" if denom else "n/a"
        label = c.get("label", score)
        print(f"  {label:<46} {c['tp']:>4} {c['fp']:>4} {c['tp_test']:>8}  {prec_s:>9}")

    # ── Ranked list preview ───────────────────────────────────────────────────
    print()
    print("RANKED LIST  (top 20 findings — risk_score descending)")
    sep()
    print(f"  {'#':>3}  {'Score':>6}  {'Label':<10}  {'Finding ID'}")
    sep("-", W)
    for i, r in enumerate(ranked[:20], 1):
        label = r["reviewer_label"].strip()
        mark = "✓" if is_tp(r) else "✗"
        print(f"  {i:>3}  {float(r.get('risk_score',0)):>6.1f}  {mark} {label:<9}  {r['finding_id']}")

    print()
    sep("═", W)
    print()


if __name__ == "__main__":
    main()
