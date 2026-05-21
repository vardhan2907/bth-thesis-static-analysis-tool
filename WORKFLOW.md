# Tool Workflow

This document describes the complete flow of the static analysis tool for detecting security misconfigurations in Django and Express applications.

---

## 1. Entry Point (CLI)

The tool provides three main commands via `scanner/cli.py`:

```bash
# Single repository analysis
python -m scanner.cli scan <path> [--out FILE] [--pretty]

# Batch scanning multiple repositories
python -m scanner.cli batch --csv <file> [--out DIR] [--pretty]

# Manual review sampling
python -m scanner.cli validate [--results FILE] [--n N] [--out FILE] [--seed INT]
```

---

## 2. Framework Detection

When you scan a repository, the tool automatically detects the framework:

```
scan_repository(target)
    ↓
Detect framework:
├── Django: looks for manage.py, settings.py, requirements.txt
└── Express: looks for package.json, app.js, server.js
    ↓
Create FileLoader (safe file discovery)
    ↓
Run appropriate rule set (Django or Express)
```

Framework detection is framework-specific and determines which set of rules to execute.

---

## 3. File Discovery (FileLoader)

The `scanner/file_loader.py` module safely discovers and reads files:

```
collect_files(target):
├── Recursively scan directory tree
├── Ignore directories:
│   ├── .git
│   ├── node_modules
│   ├── venv
│   └── __pycache__
├── Allow file extensions:
│   ├── .py (Django source)
│   ├── .js, .ts (Express source)
│   ├── .json (config files)
│   ├── .txt, .env, .example (secrets/config)
├── Safety limits:
│   ├── Maximum 10,000 files
│   └── Maximum 1GB total size
└── Encoding handling:
    ├── Try UTF-8 first
    └── Fallback to Latin-1 (prevent crashes)
```

This ensures the tool handles diverse projects safely without scanning unnecessary files or crashing on encoding issues.

---

## 4. Rule Execution

Once the framework is identified, the tool runs framework-specific rules using regex pattern matching:

### Django Rules (7 rules)

Located in `scanner/rules/django_rules.py`:

| Rule ID | Name | Detection |
|---------|------|-----------|
| DJ-DEBUG-001 | Debug Mode Enabled | `DEBUG=True` in settings files |
| DJ-SECRET-001 | Hardcoded Secret Key | Hardcoded `SECRET_KEY` literals (excludes `os.environ` patterns) |
| DJ-HOSTS-001 | Overly Permissive ALLOWED_HOSTS | `ALLOWED_HOSTS=['*']` or `[]` |
| DJ-COOKIE-001 | Missing SESSION_COOKIE_SECURE | Missing or `False` `SESSION_COOKIE_SECURE` setting |
| DJ-COOKIE-002 | SESSION_COOKIE_HTTPONLY Disabled | Explicit `SESSION_COOKIE_HTTPONLY=False` |
| DJ-CSRF-001 | CSRF Protection Disabled | `@csrf_exempt` decorator usage |
| DJ-ERROR-001 | Debug Error Exposure | `DEBUG_PROPAGATE_EXCEPTIONS=True` or `traceback.format_exc()` in views |

### Express Rules (7 rules)

Located in `scanner/rules/express_rules.py`:

| Rule ID | Name | Detection |
|---------|------|-----------|
| EX-HELMET-001 | Missing Helmet Middleware | No `helmet()` middleware in app setup |
| EX-CORS-001 | Insecure CORS Configuration | `origin:'*'` combined with `credentials:true` |
| EX-COOKIE-001 | Missing Cookie Security Flags | `res.cookie()` without `httpOnly`, `secure`, or `sameSite` |
| EX-RATE-001 | Missing Rate Limiting | Auth routes (login/register) without rate-limit middleware |
| EX-ERROR-001 | Error Stack Exposure | `res.send(err.stack)` or `res.send(err)` patterns |
| EX-AUTHZ-001 | Missing Authorization Checks | Sensitive routes (admin/dashboard/users) without auth middleware |
| EX-JSON-001 | Missing JSON Body Size Limit | `express.json()` without `limit` option |

Each rule uses regex patterns to scan file contents and identify violations.

---

## 5. Risk Scoring

For each finding, the tool calculates a risk score using four factors:

```
scanner/scoring.py

For each finding:
├── Retrieve rule's risk factors:
│   ├── E (Exploitability): 1–5 (how easy to exploit)
│   ├── I (Impact): 1–5 (damage/harm if exploited)
│   ├── D (Detectability): 1–5 (how hard to detect)
│   └── P (Prevalence): 1–5 (how common the misconfiguration)
│
├── Calculate risk score: (E + I + D + P) / 2
│   └── Range: 2.0 (minimum) to 10.0 (maximum)
│
└── Map to severity tier:
    ├── 2.0–2.5 → Low
    ├── 2.6–5.0 → Medium
    ├── 5.1–7.5 → High
    └── 7.6–10.0 → Critical
```

**Example:**

For DJ-DEBUG-001 (DEBUG=True):
```
E=4 (easy to find and exploit)
I=4 (exposes sensitive configuration)
D=4 (easy to detect in code)
P=4 (common in development)

risk_score = (4+4+4+4)/2 = 8.0 → Critical
```

---

## 6. Report Generation

The tool generates a structured JSON report with all findings:

```
scanner/models.py

ScanReport {
  "project_name": "django-jazzmin",
  "framework": "django",
  "scanned_files_count": 150,

  "findings": [
    {
      "rule_id": "DJ-DEBUG-001",
      "rule_name": "Debug Mode Enabled",
      "category": "misconfiguration",
      "description": "DEBUG is enabled in production settings",

      "evidence": {
        "file_path": "app/settings/production.py",
        "line": 42,
        "snippet": "DEBUG = True"
      },

      "risk_factors": {
        "E": 4,  # Exploitability
        "I": 4,  # Impact
        "D": 4,  # Detectability
        "P": 4   # Prevalence
      },

      "risk_score": 8.0,
      "severity": "Critical",

      "recommendation": "Set DEBUG=False in production settings. Use environment variables to manage settings per environment."
    }
  ],

  "summary": {
    "counts_by_severity": {
      "Critical": 3,
      "High": 5,
      "Medium": 2,
      "Low": 0
    },
    "counts_by_category": {
      "misconfiguration": 7,
      "authentication": 3
    }
  }
}
```

**Report Files:**
- Single scan: `report.json` (or `--out FILE` if specified)
- Batch scan: `<output_dir>/<project_name>/report.json` per project

---

## 7. Batch Mode (Multiple Repositories)

For scanning multiple repositories, use batch mode:

```
scanner/batch.py

run_batch(projects.csv, output_dir, pretty=False):
    ↓
Read CSV file (columns: project_name, repo_path)
    ↓
For each project:
├── scan_repository(repo_path)
├── Generate <output_dir>/<project_name>/report.json
└── Aggregate findings
    ↓
Output:
├── Individual JSON reports per project
└── results.csv (flattened all findings)
```

**CSV Input Format** (`projects.csv`):

```
project_name,repo_path
django-jazzmin,/path/to/django-jazzmin
sentry,/path/to/sentry
myapp,./local/path
```

**CSV Output** (`results.csv`):

```
finding_id,project_name,framework,rule_id,rule_name,category,severity,risk_score,file_path,line,snippet,recommendation
finding_1,django-jazzmin,django,DJ-DEBUG-001,Debug Mode Enabled,misconfiguration,Critical,8.0,settings.py,42,DEBUG = True,Set DEBUG=False...
finding_2,django-jazzmin,django,DJ-SECRET-001,Hardcoded Secret Key,authentication,8.5,settings.py,15,SECRET_KEY = 'abc123',Use environment variables...
```

---

## 8. Validation Sampling (Manual Review)

After batch scanning, you can sample findings for manual review and accuracy assessment:

```
scanner/validate.py

run_validate(results.csv, output_file, n=50, seed=None):
    ↓
Perform stratified sampling:
├── Group findings by severity tier
├── Sample proportionally from each tier:
│   ├── Low: ceil(n% of Low findings)
│   ├── Medium: ceil(n% of Medium findings)
│   ├── High: ceil(n% of High findings)
│   └── Critical: ceil(n% of Critical findings)
└── Guarantee minimum 1 sample per tier (if present)
    ↓
Output: validation_template.csv
```

**Validation Template** (`validation_template.csv`):

```
finding_id,project_name,rule_id,rule_name,severity,risk_score,file_path,line,snippet,reviewer_label,notes
finding_1,django-jazzmin,DJ-DEBUG-001,Debug Mode Enabled,Critical,8.0,settings.py,42,DEBUG = True,[REVIEWER FILLS],
finding_5,django-jazzmin,DJ-COOKIE-001,Missing SESSION_COOKIE_SECURE,High,6.5,settings.py,78,# SESSION_COOKIE_SECURE,[REVIEWER FILLS],
```

**Reviewer fills in:**
- `reviewer_label`: TP (True Positive), FP (False Positive), FN (False Negative)
- `notes`: Any additional comments or observations

This enables accuracy assessment and validation of tool results.

---

## 9. Complete End-to-End Example

Here's a complete workflow from start to finish:

### Step 1: Scan a Single Repository

```bash
python -m scanner.cli scan /path/to/django-app --out report.json
```

**What happens:**
```
Scan /path/to/django-app
    ↓
Detect framework: Django (found manage.py, settings.py)
    ↓
Discover files:
├── Scan 150 Python files
├── Ignore .git/, venv/, __pycache__/
├── Safe UTF-8 encoding handling
    ↓
Execute 7 Django rules:
├── DJ-DEBUG-001: Found DEBUG=True in settings/production.py (line 42)
├── DJ-SECRET-001: Found SECRET_KEY = 'hardcoded-value' (line 15)
├── DJ-HOSTS-001: Found ALLOWED_HOSTS=['*'] (line 78)
├── DJ-COOKIE-001: Missing SESSION_COOKIE_SECURE (line 95)
├── DJ-COOKIE-002: Found SESSION_COOKIE_HTTPONLY=False (line 96)
├── DJ-CSRF-001: Found @csrf_exempt on view (accounts/views.py:42)
└── DJ-ERROR-001: Found traceback.format_exc() (error_handler.py:28)
    ↓
Score each finding:
├── DJ-DEBUG-001: (4,4,4,4)/2 = 8.0 → Critical
├── DJ-SECRET-001: (5,5,4,4)/2 = 9.5 → Critical
├── DJ-HOSTS-001: (4,4,3,3)/2 = 7.0 → High
├── DJ-COOKIE-001: (3,4,2,4)/2 = 6.5 → High
├── DJ-COOKIE-002: (2,3,2,2)/2 = 4.5 → Medium
├── DJ-CSRF-001: (3,4,3,3)/2 = 6.5 → High
└── DJ-ERROR-001: (4,4,3,4)/2 = 7.5 → High
    ↓
Generate report.json: 2 Critical, 4 High, 1 Medium
```

### Step 2: Batch Scan Multiple Repositories

```bash
python -m scanner.cli batch --csv projects.csv --out results/
```

**Output:**
```
results/
├── django-jazzmin/
│   └── report.json (20 findings)
├── sentry/
│   └── report.json (15 findings)
└── results.csv (35 total findings)
```

### Step 3: Sample Findings for Manual Review

```bash
python -m scanner.cli validate --results results.csv --n 10 --out validation.csv
```

**Output:**
```
validation.csv (10 stratified samples):
├── 1 Low severity finding
├── 2 Medium severity findings
├── 4 High severity findings
└── 3 Critical severity findings
```

Reviewer fills in `reviewer_label` and `notes` for each finding.

---

## Tool Architecture Summary

```
Entry Point (CLI)
    ↓
Framework Detection
    ↓
File Discovery (FileLoader)
    ↓
Rule Execution (Regex Patterns)
    ↓
Risk Scoring (E/I/D/P Formula)
    ↓
Report Generation (JSON)
    ↓
Batch Aggregation (CSV)
    ↓
Validation Sampling (Manual Review)
```

Each component is independent and can be run standalone or as part of the pipeline.

---

## Files Involved

| File | Purpose |
|------|---------|
| `scanner/cli.py` | Command-line interface (entry point) |
| `scanner/engine.py` | Framework detection and orchestration |
| `scanner/file_loader.py` | Safe file discovery and reading |
| `scanner/rules/django_rules.py` | 7 Django security rules |
| `scanner/rules/express_rules.py` | 7 Express security rules |
| `scanner/scoring.py` | Risk scoring (E/I/D/P formula) |
| `scanner/models.py` | Data models (Finding, ScanReport, etc.) |
| `scanner/batch.py` | Batch scanning orchestration |
| `scanner/validate.py` | Validation sampling for manual review |

---

## Next Steps

1. **Scan your repository** to identify security misconfigurations
2. **Review findings** in the generated JSON report
3. **Assess severity** using the risk score and recommendations
4. **Fix issues** starting with Critical/High severity findings
5. **Validate accuracy** using the sampling tool for manual review

See [README.md](README.md) for complete command documentation and [RULES.md](RULES.md) for detailed rule specifications.
