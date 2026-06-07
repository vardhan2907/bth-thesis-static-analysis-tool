# Web App Misconfiguration Risk Scanner

A lightweight **rule-based static analysis tool** that detects application-level
security misconfigurations in **Django** and **Express** codebases and produces
structured JSON reports with risk-based prioritisation.

Built as part of a BSc thesis at Blekinge Institute of Technology (BTH), June 2026.
Not a penetration-testing or exploitation tool.

> **Thesis evaluation scope:** The thesis evaluation covers **12 rules**
> (7 Django + 5 Express: EX-HELMET-001, EX-RATE-001, EX-AUTHZ-001,
> EX-JSON-001, EX-COOKIE-001). Two additional Express rules — EX-CORS-001
> and EX-ERROR-001 — are implemented in the tool but were not included in
> the thesis evaluation dataset. All precision and prioritization results
> reported in the thesis (Chapters 4 and 5) relate exclusively to those 12 rules.

---

## Requirements

- Python 3.10 or later
- No third-party packages required (standard library only)

---

## Installation

```bash
git clone <repo-url>
cd Tool
# No pip install needed — run as a package directly:
python3 -m scanner --help
```

---

## Commands

### `scan` — scan a single repository

```bash
python3 -m scanner scan <path-to-repo>
python3 -m scanner scan <path-to-repo> --out outputs/report.json --pretty
```

| Argument     | Description                             |
| ------------ | --------------------------------------- |
| `path`       | Path to a cloned local repository       |
| `--out FILE` | Write JSON to file instead of stdout    |
| `--pretty`   | Pretty-print (indent=2) the JSON output |

**Example output** (`--pretty`):

```json
{
  "project_name": "my-django-app",
  "framework": "django",
  "scanned_files_count": 42,
  "findings": [
    {
      "rule_id": "DJ-DEBUG-001",
      "rule_name": "DEBUG mode enabled",
      "category": "security_misconfiguration",
      "description": "Django's DEBUG=True exposes full stack traces ...",
      "evidence": {
        "file_path": "myapp/settings.py",
        "line": 12,
        "snippet": "DEBUG = True"
      },
      "recommendation": "Set DEBUG = False for all production deployments.",
      "risk_factors": { "E": 4, "I": 4, "D": 4, "P": 4 },
      "risk_score": 8.0,
      "severity": "Critical"
    }
  ],
  "summary": {
    "total_findings": 1,
    "counts_by_severity": { "Critical": 1 },
    "counts_by_category": { "security_misconfiguration": 1 }
  },
  "errors": []
}
```

---

### `batch` — scan multiple repositories

```bash
python3 -m scanner batch --csv data/projects.csv
python3 -m scanner batch --csv data/projects.csv --out outputs/ --pretty
```

| Argument     | Description                                      |
| ------------ | ------------------------------------------------ |
| `--csv FILE` | CSV file listing repositories (see format below) |
| `--out DIR`  | Output directory (default: `outputs/`)           |
| `--pretty`   | Pretty-print per-project JSON reports            |

**Input CSV format** (`data/projects.csv`):

```csv
path,project_name
/path/to/cloned/django-repo,my-django-app
/path/to/cloned/express-repo,my-express-app
```

- `path` — absolute or relative (to the CSV file) path to a cloned repo
- `project_name` — optional display name; falls back to directory name

**Outputs produced:**

```
outputs/
  my-django-app/report.json      ← full JSON report per project
  my-express-app/report.json
  results.csv                    ← one row per finding, all projects
```

**`results.csv` columns:**
`finding_id`, `project_name`, `framework`, `rule_id`, `rule_name`,
`category`, `severity`, `risk_score`, `file_path`, `line`, `snippet`,
`recommendation`

---

### `validate` — sample findings for manual review

```bash
python3 -m scanner validate
python3 -m scanner validate --results outputs/results.csv --n 100 --out outputs/validation_template.csv --seed 42
```

| Argument         | Description                                                               |
| ---------------- | ------------------------------------------------------------------------- |
| `--results FILE` | Path to `results.csv` (default: `outputs/results.csv`)                    |
| `--n N`          | Number of findings to sample (default: 100)                               |
| `--out FILE`     | Output path for the template (default: `outputs/validation_template.csv`) |
| `--seed INT`     | Random seed for reproducible sampling                                     |

> **Replication note:** The thesis evaluation used `--seed 42` and `--n 100`
> to produce the stratified validation sample of 100 findings (89% coverage
> of all 112 findings) reported in Section 4.2 of the thesis. Use these
> values to reproduce the exact validation sample.

Produces a stratified sample (proportional across severity tiers) with blank
`reviewer_label` and `notes` columns ready for human annotation:

```csv
finding_id,rule_id,severity,...,reviewer_label,notes
proj__DJ-DEBUG-001__1,DJ-DEBUG-001,Critical,...,,
```

Reviewers fill `reviewer_label` with `TP`, `FP`, or `Unclear`.

---

## Output Schema

### `ScanReport`

| Field                        | Type                                     | Description                         |
| ---------------------------- | ---------------------------------------- | ----------------------------------- |
| `project_name`               | string                                   | Directory name or CSV-supplied name |
| `framework`                  | `"django"` \| `"express"` \| `"unknown"` | Detected framework                  |
| `scanned_files_count`        | int                                      | Number of files analysed            |
| `findings`                   | Finding[]                                | List of findings (may be empty)     |
| `summary.total_findings`     | int                                      |                                     |
| `summary.counts_by_severity` | object                                   | e.g. `{"Critical": 2, "High": 5}`   |
| `summary.counts_by_category` | object                                   | e.g. `{"session_security": 3}`      |
| `errors`                     | string[]                                 | Non-fatal scan errors               |

### `Finding`

| Field                  | Type                                | Description                                            |
| ---------------------- | ----------------------------------- | ------------------------------------------------------ |
| `rule_id`              | string                              | e.g. `DJ-DEBUG-001`                                    |
| `rule_name`            | string                              | Short human-readable name                              |
| `category`             | string                              | Rule category                                          |
| `description`          | string                              | Why this matters                                       |
| `evidence.file_path`   | string                              | Relative path to the file                              |
| `evidence.line`        | int \| null                         | Line number of match                                   |
| `evidence.snippet`     | string \| null                      | Matching source line                                   |
| `recommendation`       | string                              | How to fix                                             |
| `risk_factors.E/I/D/P` | int 1--5                            | Exploitability / Impact / Discoverability / Prevalence |
| `risk_score`           | float 0--10                         | `(E+I+D+P)/2`                                          |
| `severity`             | `Low`\|`Medium`\|`High`\|`Critical` | Mapped from risk_score                                 |

**Severity thresholds:**

| Severity | risk_score range |
| -------- | ---------------- |
| Critical | 7.6 -- 10.0      |
| High     | 5.1 -- 7.5       |
| Medium   | 2.6 -- 5.0       |
| Low      | 0.0 -- 2.5       |

---

## Rule Reference

### Django rules (7 rules — all evaluated in thesis)

| Rule ID       | Name                             | Trigger                                                  |
| ------------- | -------------------------------- | -------------------------------------------------------- |
| DJ-DEBUG-001  | DEBUG mode enabled               | `DEBUG = True` in any settings file                      |
| DJ-SECRET-001 | Hardcoded SECRET_KEY             | `SECRET_KEY = '...'` literal string (not env var)        |
| DJ-HOSTS-001  | ALLOWED_HOSTS unsafe             | `ALLOWED_HOSTS = ['*']` or `[]`                          |
| DJ-COOKIE-001 | SESSION_COOKIE_SECURE missing    | Absent from settings (default=False) or explicitly False |
| DJ-COOKIE-002 | SESSION_COOKIE_HTTPONLY disabled | Explicitly set to False                                  |
| DJ-CSRF-001   | @csrf_exempt decorator used      | `@csrf_exempt` in any `.py` file                         |
| DJ-ERROR-001  | Verbose error leakage            | `traceback.format_exc()` in view code                    |

### Express rules (7 implemented / 5 evaluated in thesis)

| Rule ID       | Name                                    | Trigger                                                       | In Thesis                   |
| ------------- | --------------------------------------- | ------------------------------------------------------------- | --------------------------- |
| EX-HELMET-001 | Helmet middleware not used              | No `helmet()` call found project-wide                         | ✅                          |
| EX-RATE-001   | No rate limiting on auth routes         | Auth-named route found, no rate-limit middleware project-wide | ✅                          |
| EX-AUTHZ-001  | Sensitive route without auth middleware | Admin/dashboard route, no auth middleware in same file        | ✅                          |
| EX-JSON-001   | JSON body parser has no size limit      | `express.json()` without `limit` option                       | ✅                          |
| EX-COOKIE-001 | Cookie missing security attributes      | `res.cookie()` without httpOnly/secure/sameSite               | ✅                          |
| EX-CORS-001   | Dangerous CORS configuration            | `origin: '*'` + `credentials: true` in same file              | ❌ not in thesis evaluation |
| EX-ERROR-001  | Stack trace sent to client              | `res.send(err.stack)` or `res.send(err)` pattern              | ❌ not in thesis evaluation |

---

## Risk Scoring

Each finding is scored using four factors rated 1--5 per rule:

| Factor                  | Description                                |
| ----------------------- | ------------------------------------------ |
| **E** — Exploitability  | How easily can an attacker exploit this?   |
| **I** — Impact          | What is the potential damage if exploited? |
| **D** — Discoverability | How easily can an attacker find this?      |
| **P** — Prevalence      | How commonly does this pattern appear?     |

```
risk_score = (E + I + D + P) / 2     range: 2.0 to 10.0
```

Scores are assigned per rule (not per instance), ensuring consistent and
transparent prioritization across findings.

---

## Known Limitations

All rules are **static pattern-matching heuristics**. This means:

- **False positives are expected.** For example:
  - `@csrf_exempt` on a genuinely public endpoint (e.g. webhook receiver) is intentional.
  - `EX-AUTHZ-001` may miss auth middleware defined in a separate file and applied via `router.use()`. This rule achieved 25% precision in thesis validation and should be treated as a low-confidence advisory indicator.
  - `EX-RATE-001` may miss rate-limiting packages not named `express-rate-limit`.
  - `EX-HELMET-001` may miss helmet configured in a separate middleware file outside the default collection scope.
  - `DJ-COOKIE-001` flags absence of `SESSION_COOKIE_SECURE` even in development-only settings files.

- **False negatives are possible.** Obfuscated or dynamically constructed patterns (e.g. `DEBUG = not IS_PROD`) are not detected.

- **Scope is limited to application code.** Server configuration (Nginx, TLS), infrastructure (Docker, Kubernetes), and dependency vulnerabilities (CVE) are out of scope.

- **No live requests are made.** This is purely static analysis of local source files.

- **Recall is not measured.** No ground-truth labelled dataset exists for this domain. See thesis Section 5.4 for a full discussion of limitations.

Use the `validate` command to sample findings for manual review before drawing conclusions.

---

## Reproducing the Thesis Results

1. Clone all 46 repositories listed in `data/projects.csv` at the recorded commit hashes.
2. Run batch scan: `python3 -m scanner batch --csv data/projects.csv --out outputs/ --pretty`
3. Draw validation sample: `python3 -m scanner validate --results outputs/results.csv --n 100 --seed 42`
4. Manually annotate `outputs/validation_template.csv` using `TP`, `FP`, or `Unclear`.

The full list of repository URLs and commit hashes is documented in `data/projects.csv`.

---

## Project Structure

```
Tool/
  scanner/
    __main__.py       entry point
    cli.py            argument parsing + command dispatch
    engine.py         orchestrates detect -> load -> run rules
    detector.py       framework detection (Django / Express)
    file_loader.py    recursive file collection + safe text reading
    models.py         Evidence, RiskFactors, Finding, ScanReport
    scoring.py        E/I/D/P risk scoring per rule
    batch.py          batch scanning + results.csv aggregation
    validate.py       stratified sampling for manual validation
    rules/
      django_rules.py   7 Django rules
      express_rules.py  7 Express rules (5 evaluated in thesis)
  tests/
    test_scanner_smoke.py   CLI + framework detection smoke tests
    test_rules.py           per-rule positive/negative tests
    test_batch.py           batch scanning tests
    test_validate.py        validation sampler tests
  data/
    projects.csv        list of repos scanned in thesis (with commit hashes)
  outputs/              scan results written here
```

---

## Citation

If you use this tool in your own research, please cite:

> N S Sai Vardhan Thummalapalli and Aditya Mani Krushna Mudam.
> _Detecting and Prioritizing Web Framework Security Misconfigurations:
> A Rule-Based Static Analysis of Django and Express._
> BSc Thesis, Faculty of Computing, Blekinge Institute of Technology, June 2026.
