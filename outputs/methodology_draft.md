# 3. Tool Design and Implementation

## 3.1 Overview

The scanner is a command-line static analysis tool written in Python 3.10 using the standard library only, with no third-party runtime dependencies. It performs purely static, file-level analysis — no code is executed, no network requests are made, and no live application state is examined. The tool accepts a repository path as input and produces a structured JSON report and a flat CSV of findings.

---

## 3.2 Scan Pipeline

The scan pipeline consists of five sequential stages:

**1. Framework Detection.**
The detector classifies each repository as `django`, `express`, or `unknown` using a priority-ordered heuristic: presence of `manage.py`, a `settings.py` file, or `django` in `requirements.txt` for Django; presence of `express` in `package.json` dependencies or an `express(` call in `app.js`/`server.js` for Express. If neither check passes, the framework is recorded as `unknown` and the repository is skipped.

**2. File Collection.**
A recursive file walker collects all files with extensions `.py`, `.js`, `.ts`, `.mjs`, `.cjs`, `.json`, `.txt`, and `.env` while skipping directories that are known to contain non-application code: `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `dist`, `build`, and `.next`.

**3. Rule Evaluation.**
Depending on the detected framework, either the Django ruleset or the Express ruleset is applied to the collected files. Each rule is implemented as a private function that applies compiled regular expressions to file content and returns zero or more `Finding` objects.

**4. Risk Scoring.**
Each finding is scored using four factors — Exploitability (E), Impact (I), Discoverability (D), and Prevalence (P) — each rated 1–5 per rule. The risk score is computed as:

```
risk_score = (E + I + D + P) / 2     range: 2.0 – 10.0
```

Severity is mapped as follows:

| Severity | Score Range |
|----------|-------------|
| Critical | 7.6 – 10.0  |
| High     | 5.1 – 7.5   |
| Medium   | 2.6 – 5.0   |
| Low      | 0.0 – 2.5   |

All rules in the current implementation score in the High–Critical range (6.0–8.0) by design, as they represent serious security misconfigurations.

**5. Report Generation.**
Findings are serialised into a JSON report per repository and aggregated into a flat `results.csv` for batch analysis.

---

## 3.3 Security Rules

The tool implements 12 rules across the two frameworks.

### Django Rules (7)

| Rule ID      | Name                              | Detection Method |
|--------------|-----------------------------------|------------------|
| DJ-DEBUG-001 | DEBUG mode enabled                | Regex match on `DEBUG = True` in any `settings*.py` file |
| DJ-SECRET-001 | Hardcoded SECRET\_KEY             | Regex match on literal string assignment; passes if environment-variable markers (`os.environ`, `os.getenv`, `decouple`, etc.) are present |
| DJ-HOSTS-001 | ALLOWED\_HOSTS empty or wildcard  | Regex match on `ALLOWED_HOSTS = []` or `ALLOWED_HOSTS = ["*"]` |
| DJ-COOKIE-001 | SESSION\_COOKIE\_SECURE not set   | Absence check: fires if `SESSION_COOKIE_SECURE` is not found in settings, or is explicitly set to `False` |
| DJ-COOKIE-002 | SESSION\_COOKIE\_HTTPONLY disabled | Presence of `SESSION_COOKIE_HTTPONLY = False` |
| DJ-CSRF-001  | @csrf\_exempt used                | Regex match on `@csrf_exempt` decorator in any `.py` file |
| DJ-ERROR-001 | Traceback exposed to client       | Regex match on `traceback.format_exc()` in any `.py` file |

### Express Rules (5)

| Rule ID      | Name                                    | Detection Method |
|--------------|-----------------------------------------|------------------|
| EX-HELMET-001 | Helmet middleware absent               | Absence of a `helmet()` call across all `.js`/`.ts` files |
| EX-RATE-001  | No rate limiting on auth routes         | Auth-keyword route regex (`login`, `register`, `signup`, `auth`, etc.) combined with absence of `rateLimit` or `express-rate-limit` anywhere in the project |
| EX-AUTHZ-001 | Sensitive route without auth middleware | Sensitive-path route regex (`admin`, `users`, `dashboard`, `profile`, etc.) combined with absence of auth middleware keywords (`verifyToken`, `isAuthenticated`, `passport.authenticate`, `authMiddleware`, etc.) on the same route |
| EX-JSON-001  | JSON body parser without size limit     | Regex match on `express.json()` or `bodyParser.json()` with no `limit` parameter |
| EX-COOKIE-001 | Cookie missing security attributes     | `res.cookie()` call found without all three of `httpOnly`, `secure`, and `sameSite` flags present in the same block |

### Risk Score Assignments

| Rule ID      | E | I | D | P | Score | Severity |
|--------------|---|---|---|---|-------|----------|
| DJ-DEBUG-001 | 4 | 4 | 4 | 4 | 8.0   | Critical |
| DJ-SECRET-001 | 5 | 5 | 3 | 3 | 8.0  | Critical |
| DJ-HOSTS-001 | 3 | 4 | 3 | 3 | 6.5   | High     |
| DJ-COOKIE-001 | 3 | 3 | 3 | 4 | 6.5  | High     |
| DJ-COOKIE-002 | 3 | 3 | 3 | 4 | 6.5  | High     |
| DJ-CSRF-001  | 4 | 4 | 3 | 3 | 7.0   | High     |
| DJ-ERROR-001 | 2 | 3 | 3 | 4 | 6.0   | High     |
| EX-HELMET-001 | 3 | 3 | 4 | 4 | 7.0  | High     |
| EX-RATE-001  | 4 | 3 | 3 | 4 | 7.0   | High     |
| EX-AUTHZ-001 | 4 | 5 | 3 | 3 | 7.5   | High     |
| EX-JSON-001  | 3 | 3 | 4 | 3 | 6.5   | High     |
| EX-COOKIE-001 | 3 | 3 | 3 | 4 | 6.5  | High     |

---

## 3.4 Batch Processing and Validation Sampling

A batch mode reads a CSV manifest (`projects.csv`, columns: `path`, `project_name`) and runs the scan pipeline over each listed repository, writing individual JSON reports and aggregating all findings into a single `results.csv`. A separate validation command draws a stratified random sample from `results.csv` — proportional to severity tier — and produces a `validation_template.csv` for manual True Positive / False Positive annotation.

---

## 3.5 Design Constraints

The tool was constrained to static analysis only. It performs no live HTTP requests, no dependency vulnerability lookups against CVE databases, no cloud or infrastructure-as-code checks, and no execution of application code. This boundary was chosen to ensure reproducibility and safety when scanning third-party open-source repositories at scale, and to keep the scope clearly focused on source-code level security misconfigurations.
