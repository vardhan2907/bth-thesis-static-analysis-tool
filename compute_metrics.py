"""
compute_metrics.py — Compute precision metrics from labeled validation_template.csv

Usage:
    python3 compute_metrics.py
    python3 compute_metrics.py --csv outputs/validation_template.csv
"""

import csv
import argparse
from collections import defaultdict

# FP root-cause categories derived from the notes column at runtime — no hardcoding needed.


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def classify(label):
    """Return 'TP', 'FP', or 'TP-TEST'."""
    if label in ("TP", "FP", "TP-TEST"):
        return label
    return label.strip().upper()


def compute_metrics(rows):
    total = len(rows)

    # ── Overall counts ────────────────────────────────────────────────────────
    counts = defaultdict(int)
    for r in rows:
        counts[classify(r["reviewer_label"])] += 1

    tp = counts["TP"]
    fp = counts["FP"]
    tp_test = counts["TP-TEST"]

    precision_strict = tp / (tp + fp) if (tp + fp) else 0          # TP only
    precision_broad = (tp + tp_test) / \
        total if total else 0       # TP + TP-TEST

    # ── Per-rule ──────────────────────────────────────────────────────────────
    rule_counts = defaultdict(lambda: defaultdict(int))
    for r in rows:
        rule_counts[r["rule_id"]][classify(r["reviewer_label"])] += 1

    # ── Per-framework ─────────────────────────────────────────────────────────
    fw_counts = defaultdict(lambda: defaultdict(int))
    for r in rows:
        fw = r.get("framework", "").strip().lower()
        if not fw:
            # derive from rule_id prefix
            fw = "django" if r["rule_id"].startswith("DJ") else "express"
        fw_counts[fw][classify(r["reviewer_label"])] += 1

    # ── FP details ────────────────────────────────────────────────────────────
    fp_rows = [r for r in rows if classify(r["reviewer_label"]) == "FP"]

    return {
        "total": total,
        "tp": tp,
        "fp": fp,
        "tp_test": tp_test,
        "precision_strict": precision_strict,
        "precision_broad": precision_broad,
        "rule_counts": rule_counts,
        "fw_counts": fw_counts,
        "fp_rows": fp_rows,
    }


def print_separator(char="─", width=72):
    print(char * width)


def print_metrics(m):
    W = 72
    print()
    print_separator("═", W)
    print(
        "  SCANNER PRECISION METRICS  —  Validation Sample (n={})".format(m["total"]))
    print_separator("═", W)

    # ── Overall ───────────────────────────────────────────────────────────────
    print()
    print("OVERALL")
    print_separator()
    print(f"  True Positives  (TP)      : {m['tp']:>4}")
    print(f"  False Positives (FP)      : {m['fp']:>4}")
    print(f"  True Pos – Test (TP-TEST) : {m['tp_test']:>4}")
    print(f"  Total sampled             : {m['total']:>4}")
    print()
    print(f"  Precision (strict TP only): {m['precision_strict']*100:>6.1f}%  "
          f"  [{m['tp']} / {m['tp'] + m['fp']}]")
    print(f"  Precision (TP + TP-TEST)  : {m['precision_broad']*100:>6.1f}%  "
          f"  [{m['tp'] + m['tp_test']} / {m['total']}]")

    # ── Per rule ──────────────────────────────────────────────────────────────
    print()
    print("PER-RULE PRECISION  (TP-TEST excluded from denominator)")
    print_separator()
    print(f"  {'Rule':<28} {'TP':>4} {'FP':>4} {'TP-TEST':>8} {'Precision':>10}")
    print_separator("-", W)
    rc = m["rule_counts"]
    for rule in sorted(rc.keys()):
        c = rc[rule]
        tp_ = c["TP"]
        fp_ = c["FP"]
        tpt_ = c["TP-TEST"]
        denom = tp_ + fp_
        prec = (tp_ / denom * 100) if denom else float("nan")
        prec_s = f"{prec:>8.1f}%" if denom else "     n/a"
        print(f"  {rule:<28} {tp_:>4} {fp_:>4} {tpt_:>8}   {prec_s}")

    # ── Per framework ─────────────────────────────────────────────────────────
    print()
    print("PER-FRAMEWORK PRECISION  (TP-TEST excluded from denominator)")
    print_separator()
    print(f"  {'Framework':<12} {'TP':>4} {'FP':>4} {'TP-TEST':>8} {'Precision':>10}")
    print_separator("-", W)
    for fw in sorted(m["fw_counts"].keys()):
        c = m["fw_counts"][fw]
        tp_ = c["TP"]
        fp_ = c["FP"]
        tpt_ = c["TP-TEST"]
        denom = tp_ + fp_
        prec = (tp_ / denom * 100) if denom else float("nan")
        prec_s = f"{prec:>8.1f}%" if denom else "     n/a"
        print(f"  {fw:<12} {tp_:>4} {fp_:>4} {tpt_:>8}   {prec_s}")

    # ── FP breakdown ──────────────────────────────────────────────────────────
    print()
    print(f"FALSE POSITIVE BREAKDOWN  (n={m['fp']})")
    print_separator()
    cause_counts = defaultdict(int)
    for r in m["fp_rows"]:
        cause_counts[r["notes"] or "No notes provided"] += 1

    for cause, cnt in sorted(cause_counts.items(), key=lambda x: -x[1]):
        print(f"  {cnt:>2}×  {cause}")

    print()
    print("  Detail:")
    print_separator("-", W)
    for r in m["fp_rows"]:
        print(f"  {r['finding_id']}")
        print(f"       Rule : {r['rule_id']}  |  Notes: {r['notes']}")
    print()
    print_separator("═", W)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Compute precision metrics from labeled validation CSV")
    parser.add_argument("--csv", default="outputs/validation_template.csv",
                        help="Path to labeled validation_template.csv")
    args = parser.parse_args()

    rows = load_csv(args.csv)
    unlabeled = [r for r in rows if not r.get("reviewer_label", "").strip()]
    if unlabeled:
        print(
            f"WARNING: {len(unlabeled)} rows have no reviewer_label — skipped.")
        rows = [r for r in rows if r.get("reviewer_label", "").strip()]

    m = compute_metrics(rows)
    print_metrics(m)


if __name__ == "__main__":
    main()
