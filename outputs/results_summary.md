# Evaluation Results Summary

---

## 1. Total Findings by Framework

| Framework | Findings | Projects with Findings |
|-----------|----------|----------------------|
| Django    | 53       | 18                   |
| Express   | 59       | 19                   |
| **Total** | **112**  | **37**               |

9 of 46 scanned repositories produced zero findings (7 framework detection failures, 2 genuinely clean).

---

## 2. Findings per Rule

| Rule ID       | Name                                  | Findings |
|---------------|---------------------------------------|----------|
| EX-RATE-001   | No rate limiting on auth routes       | 20       |
| EX-HELMET-001 | Helmet middleware not used            | 16       |
| EX-JSON-001   | JSON body parser no size limit        | 16       |
| DJ-COOKIE-001 | SESSION_COOKIE_SECURE not set         | 15       |
| DJ-DEBUG-001  | DEBUG mode enabled                    | 10       |
| DJ-HOSTS-001  | ALLOWED_HOSTS empty or wildcard       | 10       |
| DJ-SECRET-001 | Hardcoded SECRET_KEY                  | 9        |
| DJ-CSRF-001   | @csrf_exempt used                     | 7        |
| EX-AUTHZ-001  | Sensitive route without auth middleware | 6      |
| DJ-ERROR-001  | traceback.format_exc() in code        | 1        |
| DJ-COOKIE-002 | SESSION_COOKIE_HTTPONLY disabled      | 1        |
| EX-COOKIE-001 | Cookie missing security attributes    | 1        |

---

## 3. Findings per Repository

| Project                        | Framework | Findings |
|--------------------------------|-----------|----------|
| multi_tenant_auth              | Django    | 8        |
| scrypta-identity               | Express   | 6        |
| robo-poet                      | Django    | 5        |
| event-management               | Express   | 5        |
| ferret                         | Express   | 5        |
| wg-ui-plus                     | Django    | 5        |
| dj-store                       | Django    | 4        |
| django-mail-auth               | Django    | 4        |
| weird-side-youtube             | Express   | 4        |
| django-todo-auth               | Django    | 4        |
| example-python-django-oidc     | Django    | 4        |
| dj-djoser                      | Django    | 4        |
| social-media-app               | Express   | 4        |
| movie-library                  | Express   | 4        |
| auth-app-server-side           | Express   | 4        |
| django-login-register          | Django    | 3        |
| sharey                         | Express   | 3        |
| natours                        | Express   | 3        |
| cse341_project                 | Express   | 3        |
| express-session-auth-starter   | Express   | 3        |
| todos-express-password         | Express   | 3        |
| whatsapp-gateway               | Express   | 3        |
| wanderlust                     | Express   | 2        |
| django-smartbase-admin         | Django    | 2        |
| shifter                        | Django    | 2        |
| django-react-auth              | Django    | 2        |
| lets-chat                      | Express   | 2        |
| user-authentication-system     | Express   | 2        |
| rietveld                       | Django    | 1        |
| edx-val                        | Django    | 1        |
| cute_prep                      | Django    | 1        |
| django-auth-backend            | Django    | 1        |
| coreproject                    | Django    | 1        |
| tangelo                        | Django    | 1        |
| expressjs-full-course          | Express   | 1        |
| shopify-node-express-app       | Express   | 1        |
| project-mgmt-graphql           | Express   | 1        |

---

## 4. Severity Distribution

| Severity | Findings | % of Total |
|----------|----------|------------|
| Critical | 19       | 17.0%      |
| High     | 93       | 83.0%      |

Critical findings are exclusively DJ-DEBUG-001 and DJ-SECRET-001 (risk score 8.0).
All other rules produce High severity findings (scores 6.0–7.5).

---

## 5. Validation Results (n=100, stratified sample)

| Rule ID       | TP | FP | TP-TEST | Precision (strict) |
|---------------|----|----|---------|-------------------|
| DJ-DEBUG-001  | 7  | 0  | 2       | 100.0%            |
| DJ-SECRET-001 | 5  | 0  | 3       | 100.0%            |
| DJ-CSRF-001   | 2  | 0  | 5       | 100.0%            |
| EX-JSON-001   | 12 | 1  | 0       | 92.3%             |
| DJ-COOKIE-001 | 11 | 1  | 3       | 91.7%             |
| EX-RATE-001   | 17 | 2  | 0       | 89.5%             |
| DJ-HOSTS-001  | 7  | 1  | 1       | 87.5%             |
| EX-HELMET-001 | 9  | 4  | 0       | 69.2%             |
| EX-AUTHZ-001  | 1  | 3  | 0       | 25.0%             |
| DJ-ERROR-001  | 0  | 1  | 0       | 0.0%              |
| EX-COOKIE-001 | 0  | 1  | 0       | 0.0%              |
| DJ-COOKIE-002 | 0  | 0  | 1       | n/a               |
| **Overall**   | **71** | **14** | **15** | **83.5%** |

- Overall precision (strict TP only): **83.5%** (71 / 85)
- Overall precision (TP + TP-TEST): **86.0%** (86 / 100)
- Django precision: **91.4%**
- Express precision: **78.0%**

---

## 6. Prioritisation Metrics (RQ2 — Ranking)

Ranked list = findings sorted by risk_score descending.
Random baseline = Monte Carlo average over 10,000 random permutations.

### Precision@K

| K   | Ranked  | Random Baseline | Δ       |
|-----|---------|-----------------|---------|
| 10  | 100.0%  | 86.1%           | +13.9%  |
| 20  | 90.0%   | 86.1%           | +3.9%   |
| 30  | 90.0%   | 86.0%           | +4.0%   |
| 50  | 86.0%   | 86.0%           | 0.0%    |

### Average Precision (AP)

| List              | AP     |
|-------------------|--------|
| Ranked            | 89.5%  |
| Random baseline   | 86.6%  |
| Improvement       | +2.8pp |

### First False Positive in Ranked List

Position **18** — `auth-app-server-side__EX-AUTHZ-001__111` (risk score 7.5).
Positions 1–17 are all confirmed true positives (Critical tier, score 8.0).
