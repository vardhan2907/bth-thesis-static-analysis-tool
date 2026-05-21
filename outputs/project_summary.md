# Project Summary — Static Security Misconfiguration Scanner
## Thesis Preparation Brief

---

## What Is This Project?

We built a **command-line static analysis tool** that automatically scans web application source code for security misconfigurations — specifically in **Django** (Python) and **Express.js** (JavaScript/Node.js) projects. The tool does not run or attack the applications; it only reads the source files.

The research question driving the project is:

> **RQ1:** Which security misconfigurations occur most frequently in small open-source web applications, and how are they distributed?
>
> **RQ2:** How accurate is the tool, and does its risk scoring model help prioritise real issues over false alarms?

---

## The Problem Being Solved

Web developers frequently ship applications with insecure default settings — things like leaving Django's DEBUG mode switched on, skipping security headers in Express, or storing secret keys directly in the source code. These are not coding bugs; they are **configuration mistakes** that are easy to overlook and hard to spot without a dedicated tool.

Existing tools (Bandit, Semgrep, njsscan) focus on code-level vulnerabilities like SQL injection or XSS. As demonstrated by running all three on the dataset, **none of them detect the types of configuration misconfigurations this tool targets** — the gap is real and documented.

---

## The Tool — How It Works

The scan pipeline has five stages:

```
Source Code
    ↓
1. Framework Detection     — is this Django or Express?
    ↓
2. File Collection         — gather relevant .py / .js files
    ↓
3. Rule Evaluation         — apply 12 regex-based detection rules
    ↓
4. Risk Scoring            — assign a numeric risk score per finding
    ↓
5. Report                  — JSON output, ranked by risk
```

**Risk scoring formula:** `risk_score = (Exploitability + Impact + Discoverability + Prevalence) / 2`

Each factor is rated 1–5 per rule. All current rules score in the High to Critical range (6.0–8.0).

| Severity | Score range |
|---|---|
| Critical | 7.6 – 10.0 |
| High | 5.1 – 7.5 |

---

## The 12 Detection Rules

### Django Rules (7)

| Rule ID | What it detects | Severity |
|---|---|---|
| DJ-DEBUG-001 | `DEBUG = True` in settings | Critical |
| DJ-SECRET-001 | Hardcoded `SECRET_KEY` in settings | Critical |
| DJ-HOSTS-001 | `ALLOWED_HOSTS = ['*']` or empty | High |
| DJ-COOKIE-001 | `SESSION_COOKIE_SECURE` not set to True | High |
| DJ-COOKIE-002 | `SESSION_COOKIE_HTTPONLY` set to False | High |
| DJ-CSRF-001 | `@csrf_exempt` decorator used on a view | High |
| DJ-ERROR-001 | `traceback.format_exc()` exposed in a response | High |

### Express.js Rules (5)

| Rule ID | What it detects | Severity |
|---|---|---|
| EX-HELMET-001 | `helmet()` security middleware not used | High |
| EX-RATE-001 | No rate limiting on authentication routes | High |
| EX-JSON-001 | `express.json()` used without a size limit | High |
| EX-AUTHZ-001 | Sensitive route without authentication middleware | High |
| EX-COOKIE-001 | Cookie set without `secure` or `httpOnly` flags | High |

---

## The Dataset

- **46 open-source GitHub repositories** — 19 Django, 27 Express.js
- All repositories contain authentication or session management code
- Range from single-developer tutorial projects to actively maintained tools
- No minimum star count, recency filter, or license restriction applied
- Collected in two phases: 20 initial (DJ02–DJ10, EX01–EX10) + 26 extended (DJ11–DJ20, EX11–EX27)

---

## RQ1 Results — What Was Found

### Overall

| Framework | Findings | Repos with findings |
|---|---|---|
| Django | 53 | 18 of 19 |
| Express | 59 | 19 of 27 |
| **Total** | **112** | **37 of 46** |

9 repos produced zero findings: 7 failed framework detection (non-standard structure), 2 were genuinely clean.

### Most Frequent Misconfigurations

| Rule | Finding count | Prevalence |
|---|---|---|
| EX-RATE-001 — No rate limiting | 20 | 68% of Express repos |
| EX-HELMET-001 — Missing Helmet | 16 | 84% of Express repos |
| EX-JSON-001 — No body size limit | 16 | 79% of Express repos |
| DJ-COOKIE-001 — Cookie not secure | 15 | 83% of Django repos |
| DJ-DEBUG-001 — DEBUG mode on | 10 | 56% of Django repos |
| DJ-HOSTS-001 — ALLOWED_HOSTS open | 10 | 56% of Django repos |
| DJ-SECRET-001 — Hardcoded secret | 9 | 50% of Django repos |

**Key takeaway:** Missing Helmet (84%) and insecure session cookies (83%) are the most widespread misconfigurations in their respective frameworks. Security misconfiguration is not rare — it is the norm in this dataset.

### Severity Split

- **Critical** (score 8.0): 19 findings — all from DEBUG mode and hardcoded SECRET_KEY
- **High** (score 6.0–7.5): 93 findings — all other rules
- No Medium or Low findings (by design — the tool only implements serious rules)

---

## RQ2 Results — Accuracy and Ranking

### Validation Method

- 100 findings manually sampled from the 112 total (89% coverage), stratified by severity, seed=42
- Each finding verified by reading the actual flagged source file at the reported line
- Labelled as: **TP** (confirmed real), **FP** (false alarm), or **TP-TEST** (correct detection but in a test/dev file only)

### Precision Results

| Metric | Value |
|---|---|
| Overall strict precision (TP only) | **83.5%** (71/85) |
| Broad precision (TP + TP-TEST) | **86.0%** (86/100) |
| Django rules precision | **91.4%** |
| Express rules precision | **78.0%** |

### Per-Rule Precision

| Rule | Precision | Notes |
|---|---|---|
| DJ-DEBUG-001 | 100% | Zero false positives |
| DJ-SECRET-001 | 100% | Zero false positives |
| DJ-CSRF-001 | 100% | Zero false positives |
| EX-JSON-001 | 92.3% | |
| DJ-COOKIE-001 | 91.7% | |
| EX-RATE-001 | 89.5% | |
| DJ-HOSTS-001 | 87.5% | |
| EX-HELMET-001 | 69.2% | Scans frontend JS in fullstack repos |
| EX-AUTHZ-001 | 25.0% | Matches page-render routes, not just auth endpoints |
| DJ-ERROR-001 | 0% | 1 finding, was FP |
| EX-COOKIE-001 | 0% | 1 finding, was FP |

**Main source of false positives:** EX-HELMET-001 flags frontend React/static JS files in fullstack monorepos instead of the Express server. EX-AUTHZ-001 matches non-credential page routes as "sensitive."

### Ranking Evaluation

The tool ranks findings by risk score. Compared to a random ordering (10,000 Monte Carlo shuffles):

| K | Ranked list | Random baseline | Improvement |
|---|---|---|---|
| Top 10 | 100.0% precision | 86.1% | +13.9% |
| Top 20 | 90.0% | 86.1% | +3.9% |
| Top 50 | 86.0% | 86.0% | 0.0% |
| Average Precision | 89.5% | 86.6% | +2.8pp |

**First false positive** in ranked order appears at **position 18** — meaning a developer reviewing findings in order would encounter 17 consecutive confirmed real issues before the first false alarm.

---

## Baseline Comparison — Does This Tool Fill a Gap?

Three established tools were run on the same 46 repositories:

| Tool | Scope | Total findings produced |
|---|---|---|
| Bandit | 19 Django repos | 87 |
| Semgrep (p/django + p/nodejs) | 46 repos | 145 |
| njsscan | 27 Express repos | 343 |

**What they found:**
- Bandit: `mark_safe` misuse, hardcoded SQL, `subprocess` shell injection, `yaml.load` — general Python code vulnerabilities
- Semgrep p/django: missing `{% csrf_token %}` in templates, open redirects
- Semgrep p/nodejs / njsscan: NoSQL injection, XSS, cookie session attributes, timing attacks

**Coverage of student tool's 12 rules:**

| Rule | Bandit | Semgrep | njsscan |
|---|---|---|---|
| DJ-DEBUG-001 | — | — | — |
| DJ-SECRET-001 | — | — | — |
| DJ-CSRF-001 | — | — | — |
| DJ-COOKIE-001 | — | — | — |
| DJ-COOKIE-002 | — | — | — |
| DJ-HOSTS-001 | — | — | — |
| DJ-ERROR-001 | — | — | — |
| EX-HELMET-001 | — | — | — |
| EX-RATE-001 | — | — | — |
| EX-JSON-001 | — | — | — |
| EX-AUTHZ-001 | — | — | — |
| EX-COOKIE-001 | — | partial | partial |

**11 of 12 rules are unique to this tool.** Existing tools target code-level vulnerabilities; this tool targets framework configuration misconfigurations. The gap is real and empirically demonstrated.

---

## Key Limitations

1. **Dataset is purposive, not random.** 46 hand-picked repos cannot generalise to all Django/Express applications or to commercial codebases.

2. **Single reviewer.** Manual validation was done by one person without a second labeller or inter-rater reliability measure (Cohen's Kappa). This is standard for BSc scope but is a formal limitation.

3. **No recall measurement.** The tool's false negative rate is unknown — we cannot say how many misconfigurations it missed because there is no complete ground-truth dataset.

4. **EX-AUTHZ-001 is over-scored.** The rule has 25% precision but a risk score of 7.5 (second highest), placing low-quality findings near the top of the ranked list. This is a known limitation of per-rule fixed scoring.

5. **Framework detection failures.** 7 of 46 repos were silently skipped because the detector could not identify the framework from the project structure.

6. **Fixed per-rule risk scores.** Two findings from the same rule get the same score regardless of context. The scoring model does not adapt to per-instance severity.

---

## What We Delivered

| Artifact | Description |
|---|---|
| `scanner/` | The static analysis tool (Python, standard library only) |
| `data/data.csv` | 46-repo dataset with metadata |
| `outputs/results.csv` | 112 findings across all repos |
| `outputs/validation_template.csv` | 100 hand-labelled findings (TP/FP/TP-TEST) |
| `compute_metrics.py` | Precision calculation script |
| `compute_ranking.py` | Precision@K and AP ranking evaluation |
| `compute_frequency.py` | RQ1 frequency and distribution analysis |
| `run_baseline.py` | Runs Bandit, Semgrep, njsscan on all repos |
| `compare_baseline.py` | Produces rule-level coverage comparison table |
| `outputs/baseline_comparison.md` | Final baseline comparison report |
| `outputs/results_summary.md` | All evaluation statistics in one place |

---

## One-Paragraph Summary (for verbal presentation)

We built a static analysis tool that scans Django and Express.js repositories for security misconfigurations — things like debug mode left on, missing security headers, or insecure cookie settings. We ran it on 46 open-source repositories and found 112 issues across 37 of them, showing that misconfiguration is widespread. We manually verified 100 findings and confirmed 83.5% precision overall, with Django rules reaching 91.4%. The risk scoring model concentrates the most reliable findings at the top — the first false positive appears only at position 18 in the ranked output. We also ran three established tools — Bandit, Semgrep, and njsscan — on the same repositories and found that they cover none of our 11 unique rules, confirming that this tool addresses a gap that existing scanners do not fill.
