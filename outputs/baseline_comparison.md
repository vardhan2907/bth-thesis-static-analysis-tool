# Baseline Tool Comparison

Comparison of the student's static analysis tool against three established tools: Bandit, Semgrep (p/django and p/nodejs), and njsscan.

---

## 1. Rule-Level Coverage

For each of the student's 12 detection rules, this table shows whether an equivalent rule exists in each external tool.

| Rule ID | Bandit | Semgrep | njsscan | Covered by any |
|---|---|---|---|---|
| DJ-DEBUG-001 | — | — | — | **unique** |
| DJ-SECRET-001 | — | — | — | **unique** |
| DJ-CSRF-001 | — | — | — | **unique** |
| DJ-COOKIE-001 | — | — | — | **unique** |
| DJ-COOKIE-002 | — | — | — | **unique** |
| DJ-HOSTS-001 | — | — | — | **unique** |
| DJ-ERROR-001 | — | — | — | **unique** |
| EX-HELMET-001 | — | — | — | **unique** |
| EX-RATE-001 | — | — | — | **unique** |
| EX-JSON-001 | — | — | — | **unique** |
| EX-AUTHZ-001 | — | — | — | **unique** |
| EX-COOKIE-001 | — | yes | yes | yes (partial) |

**1 rules** have partial coverage in at least one existing tool. **11 rules** are unique to the student's tool.

### Notes per rule

- **DJ-DEBUG-001**: No existing tool detected DEBUG=True in settings.py. Bandit has no Django settings check; Semgrep p/django fired only django-no-csrf-token and open-redirect rules on this dataset. Unique to student's tool.
- **DJ-SECRET-001**: Bandit's hardcoded-password rules (B105–B107) did not fire for any Django SECRET_KEY value in this dataset. Semgrep p/django did not flag hardcoded SECRET_KEY. Unique to student's tool.
- **DJ-CSRF-001**: Semgrep p/django fired django-no-csrf-token (missing {% csrf_token %} in templates) which is a different issue from @csrf_exempt (disabling CSRF protection on a view). Bandit has no CSRF check. Unique to student's tool.
- **DJ-COOKIE-001**: SESSION_COOKIE_SECURE not set: not detected by any tool on this dataset. Unique to student's tool.
- **DJ-COOKIE-002**: SESSION_COOKIE_HTTPONLY disabled: not detected by any tool on this dataset. Unique to student's tool.
- **DJ-HOSTS-001**: ALLOWED_HOSTS wildcard or empty: not covered by any existing tool. Unique to student's tool.
- **DJ-ERROR-001**: traceback.format_exc() exposure in HTTP responses: not covered by any existing tool. Unique to student's tool.
- **EX-HELMET-001**: Missing helmet() middleware: not detected by Semgrep p/nodejs or njsscan. Both tools detect code-level vulnerabilities (XSS, NoSQL injection) but not the absence of security middleware. Unique to student's tool.
- **EX-RATE-001**: Missing rate limiting on auth routes: not detected by any existing tool. Unique to student's tool.
- **EX-JSON-001**: express.json() without size limit: not detected by any existing tool. Unique to student's tool.
- **EX-AUTHZ-001**: Sensitive route without auth middleware: not detected by any existing tool. Unique to student's tool.
- **EX-COOKIE-001**: Cookie security attributes: Semgrep p/nodejs and njsscan both flag missing secure/httpOnly/samesite on session cookies. Partial overlap with student's EX-COOKIE-001 rule, which checks res.cookie() calls for missing secure and httpOnly flags.

---

## 2. Empirical Finding Counts

Finding counts produced by each tool on the same repositories. `n/a` = tool not applicable to this framework. `ERR` = tool failed or no output.

| Repo | Framework | Student tool | Bandit | Semgrep | njsscan |
|---|---|---|---|---|---|
| DJ02 | django | 1 | 13 | 20 | n/a |
| DJ03 | django | 1 | 1 | 0 | n/a |
| DJ04 | django | 1 | 0 | 3 | n/a |
| DJ05 | django | 5 | 9 | 0 | n/a |
| DJ06 | django | 8 | 6 | 0 | n/a |
| DJ07 | django | 3 | 0 | 0 | n/a |
| DJ08 | django | 4 | 0 | 4 | n/a |
| DJ09 | django | 1 | 0 | 0 | n/a |
| DJ10 | django | 4 | 0 | 0 | n/a |
| DJ11 | django | 4 | 0 | 0 | n/a |
| DJ12 | django | 1 | 2 | 0 | n/a |
| DJ13 | django | 2 | 39 | 5 | n/a |
| DJ14 | django | 2 | 11 | 3 | n/a |
| DJ15 | django | 5 | 2 | 0 | n/a |
| DJ16 | django | 4 | 1 | 1 | n/a |
| DJ17 | django | 0 | 3 | 7 | n/a |
| DJ18 | django | 1 | 0 | 0 | n/a |
| DJ19 | django | 2 | 0 | 0 | n/a |
| DJ20 | django | 4 | 0 | 0 | n/a |
| EX01 | express | 4 | n/a | 7 | 10 |
| EX02 | express | 0 | n/a | 0 | 0 |
| EX03 | express | 3 | n/a | 12 | 14 |
| EX04 | express | 2 | n/a | 4 | 10 |
| EX05 | express | 5 | n/a | 16 | 16 |
| EX06 | express | 6 | n/a | 6 | 22 |
| EX07 | express | 0 | n/a | 1 | 2 |
| EX08 | express | 3 | n/a | 0 | 17 |
| EX09 | express | 5 | n/a | 7 | 9 |
| EX10 | express | 3 | n/a | 7 | 8 |
| EX11 | express | 2 | n/a | 0 | 12 |
| EX12 | express | 0 | n/a | 4 | 27 |
| EX13 | express | 4 | n/a | 0 | 10 |
| EX14 | express | 3 | n/a | 0 | 0 |
| EX15 | express | 3 | n/a | 7 | 22 |
| EX16 | express | 0 | n/a | 9 | 14 |
| EX17 | express | 0 | n/a | 0 | 2 |
| EX18 | express | 0 | n/a | 1 | 8 |
| EX19 | express | 0 | n/a | 0 | 30 |
| EX20 | express | 1 | n/a | 1 | 0 |
| EX21 | express | 3 | n/a | 1 | 29 |
| EX22 | express | 0 | n/a | 6 | 61 |
| EX23 | express | 1 | n/a | 0 | 2 |
| EX24 | express | 1 | n/a | 0 | 0 |
| EX25 | express | 4 | n/a | 6 | 8 |
| EX26 | express | 2 | n/a | 7 | 6 |
| EX27 | express | 4 | n/a | 0 | 4 |

---

## 3. Key Observations

- **Bandit** (19 Django repos): fired 87 findings across 14 rule categories (mark_safe, hashlib, hardcoded SQL, subprocess, etc.). None of these overlap with any of the student's 7 Django rules. Bandit targets general Python code vulnerabilities, not Django settings misconfigurations.
- **Semgrep p/django** (19 Django repos): fired on django-no-csrf-token (missing {% csrf_token %} in templates), open-redirect, and two other rules. None cover DEBUG mode, SECRET_KEY, ALLOWED_HOSTS, or session cookie settings. The django-no-csrf-token rule detects a different issue from DJ-CSRF-001 (@csrf_exempt disables CSRF for a whole view; the template token is a separate concern).
- **Semgrep p/nodejs** (27 Express repos): fired on cookie session attributes (no-secure, no-httponly, no-domain, no-path, no-expires, default-name), hardcoded session secrets, XSS, and path traversal. The cookie-settings rules partially overlap with EX-COOKIE-001. None cover Helmet, rate limiting, body parser size, or authorization middleware absence.
- **njsscan** (27 Express repos): fired on NoSQL injection, XSS, cookie session attributes, timing attacks, insecure random, and path traversal. The cookie_session_no_secure and cookie_session_no_samesite rules partially overlap with EX-COOKIE-001. None cover Helmet, rate limiting, or body parser size.
- **11 of 12 student rules are unique** to the student's tool. Only EX-COOKIE-001 has partial coverage in existing tools (Semgrep and njsscan). All Express middleware composition rules (EX-HELMET-001, EX-RATE-001, EX-JSON-001) and all Django settings rules (DJ-DEBUG-001, DJ-SECRET-001, DJ-HOSTS-001, DJ-COOKIE-001, DJ-COOKIE-002, DJ-CSRF-001, DJ-ERROR-001) are unique to the student's tool.
