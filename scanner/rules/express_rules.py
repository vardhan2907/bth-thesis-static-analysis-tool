from __future__ import annotations

import re
from pathlib import Path

from ..file_loader import FileLoader
from ..models import Evidence, Finding
from ..scoring import score_for_rule

# ── Compiled patterns ─────────────────────────────────────────────────────────

_HELMET_USAGE = re.compile(r"helmet\s*\(")

# EX-CORS-001
_CORS_ORIGIN_STAR = re.compile(r"""origin\s*:\s*['"][*]['"]""")
_CORS_CREDENTIALS_TRUE = re.compile(r"credentials\s*:\s*true", re.IGNORECASE)
_CORS_HEADER_ORIGIN_STAR = re.compile(r"""Access-Control-Allow-Origin['"]\s*,\s*['"][*]['"]""")
_CORS_HEADER_CREDENTIALS = re.compile(r"""Access-Control-Allow-Credentials['"]\s*,\s*['"]true['"]""")

# EX-COOKIE-001
_COOKIE_SET = re.compile(r"res\.cookie\s*\(")
_HTTPONLY_TRUE = re.compile(r"httpOnly\s*:\s*true", re.IGNORECASE)
_SECURE_TRUE = re.compile(r"\bsecure\s*:\s*true", re.IGNORECASE)
_SAME_SITE = re.compile(r"sameSite\s*:", re.IGNORECASE)

# EX-RATE-001
_AUTH_ROUTE = re.compile(
    r"""(?:app|router)\.\w+\s*\(\s*['"][^'"]*"""
    r"""(?:login|logout|register|auth|signin|signup|password)[^'"]*['"]""",
    re.IGNORECASE,
)
_RATE_LIMIT_PRESENT = re.compile(r"rateLimit|rate.limit|express-rate-limit", re.IGNORECASE)

# EX-ERROR-001
_ERR_STACK_IN_RES = re.compile(
    r"res\.(?:send|json)\s*\([^)]*(?:err|error)\.stack", re.IGNORECASE
)
_ERR_SEND_RAW = re.compile(r"res\.send\s*\(\s*(?:err|error)\s*\)", re.IGNORECASE)

# EX-AUTHZ-001
_SENSITIVE_ROUTE = re.compile(
    r"""(?:app|router)\.\w+\s*\(\s*['"][^'"]*"""
    r"""(?:admin|dashboard|users|profile|account|settings)[^'"]*['"]""",
    re.IGNORECASE,
)
_AUTH_MIDDLEWARE = re.compile(
    r"isAuthenticated|requireAuth|verifyToken|authenticate|authorize"
    r"|passport\.authenticate|jwt\.verify|authMiddleware",
    re.IGNORECASE,
)

# EX-JSON-001
_JSON_NO_LIMIT = re.compile(
    r"""(?:express\.json|bodyParser\.json)\s*\(\s*(?:\{\s*\})?\s*\)"""
)
_JSON_WITH_LIMIT = re.compile(
    r"""(?:express\.json|bodyParser\.json)\s*\([^)]*limit"""
)

_NODE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _node_files(loader: FileLoader) -> list[Path]:
    return [p for p in loader.list_files() if p.suffix.lower() in _NODE_SUFFIXES]


def _make(rule_id: str, rule_name: str, category: str, description: str,
          evidence: Evidence, recommendation: str) -> Finding:
    risk_factors, risk_score, severity = score_for_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        rule_name=rule_name,
        category=category,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        risk_factors=risk_factors,
        risk_score=risk_score,
        severity=severity,
    )


# ── Rule implementations ──────────────────────────────────────────────────────

def _check_helmet(root: Path, loader: FileLoader) -> list[Finding]:
    scanned: list[str] = []
    for path in _node_files(loader):
        content = loader.read_text(path)
        if not content.strip():
            continue
        scanned.append(str(path.relative_to(root)))
        if _HELMET_USAGE.search(content):
            return []  # found — no finding

    preview = ", ".join(scanned[:5]) if scanned else "none"
    return [_make(
        rule_id="EX-HELMET-001",
        rule_name="Helmet middleware not used",
        category="security_headers",
        description=(
            "Helmet sets important HTTP security headers (X-Frame-Options, "
            "X-Content-Type-Options, HSTS, CSP, etc.). Without it the app is missing "
            "baseline browser-level protections. "
            "(Heuristic: no helmet() call found in scanned Node.js files.)"
        ),
        evidence=Evidence(file_path=preview, snippet="No helmet() call found."),
        recommendation="npm install helmet  and add app.use(helmet()) in your Express app setup.",
    )]


def _check_cors(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _node_files(loader):
        content = loader.read_text(path)
        if not content.strip():
            continue

        cors_wildcard = (
            _CORS_ORIGIN_STAR.search(content) and _CORS_CREDENTIALS_TRUE.search(content)
        )
        manual_wildcard = (
            _CORS_HEADER_ORIGIN_STAR.search(content) and _CORS_HEADER_CREDENTIALS.search(content)
        )
        if not (cors_wildcard or manual_wildcard):
            continue

        line_no, snippet = None, None
        for i, line in enumerate(content.splitlines(), 1):
            if _CORS_ORIGIN_STAR.search(line) or _CORS_HEADER_ORIGIN_STAR.search(line):
                line_no, snippet = i, line.strip()
                break

        findings.append(_make(
            rule_id="EX-CORS-001",
            rule_name="Dangerous CORS configuration",
            category="cors_misconfiguration",
            description=(
                "CORS is configured with both a wildcard origin ('*') and "
                "credentials: true in the same file. This combination is insecure: "
                "an attacker's site can make credentialed cross-origin requests to your API. "
                "Browsers block this per-spec, but the intent to allow cross-origin credentials "
                "indicates a dangerous configuration that is often later 'fixed' insecurely."
            ),
            evidence=Evidence(
                file_path=str(path.relative_to(root)),
                line=line_no,
                snippet=snippet,
            ),
            recommendation=(
                "Never combine a wildcard origin with credentials: true. "
                "Use an explicit allowlist: cors({ origin: 'https://yourfrontend.com', credentials: true })"
            ),
        ))
    return findings


def _check_cookies(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _node_files(loader):
        content = loader.read_text(path)
        if not _COOKIE_SET.search(content):
            continue

        missing: list[str] = []
        if not _HTTPONLY_TRUE.search(content):
            missing.append("httpOnly")
        if not _SECURE_TRUE.search(content):
            missing.append("secure")
        if not _SAME_SITE.search(content):
            missing.append("sameSite")
        if not missing:
            continue

        line_no, snippet = None, None
        for i, line in enumerate(content.splitlines(), 1):
            if _COOKIE_SET.search(line):
                line_no, snippet = i, line.strip()
                break

        findings.append(_make(
            rule_id="EX-COOKIE-001",
            rule_name="Cookie missing security attributes",
            category="session_security",
            description=(
                f"res.cookie() is called but the following security flags were not found "
                f"in this file: {', '.join(missing)}. "
                f"Missing httpOnly exposes cookies to XSS; missing secure allows transmission "
                f"over plain HTTP; missing sameSite enables CSRF attacks. "
                f"(Heuristic: checks for flag presence anywhere in the file.)"
            ),
            evidence=Evidence(
                file_path=str(path.relative_to(root)),
                line=line_no,
                snippet=snippet,
            ),
            recommendation=(
                "Set all three flags: "
                "res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'Strict' })"
            ),
        ))
    return findings


def _check_rate_limit(root: Path, loader: FileLoader) -> list[Finding]:
    all_files = _node_files(loader)
    if not all_files:
        return []

    # If rate limiting is present anywhere in the project, skip
    if any(_RATE_LIMIT_PRESENT.search(loader.read_text(p)) for p in all_files):
        return []

    # Generate one finding per file that contains auth-related routes
    findings: list[Finding] = []
    for path in all_files:
        content = loader.read_text(path)
        line_no, snippet = None, None
        for i, line in enumerate(content.splitlines(), 1):
            if _AUTH_ROUTE.search(line):
                line_no, snippet = i, line.strip()
                break
        if line_no is None:
            continue

        findings.append(_make(
            rule_id="EX-RATE-001",
            rule_name="No rate limiting on auth routes",
            category="brute_force_protection",
            description=(
                "An authentication-related route was found but no rate-limiting middleware "
                "(express-rate-limit or similar) was detected anywhere in the project. "
                "Without rate limiting, login and registration endpoints are vulnerable to "
                "brute-force and credential-stuffing attacks. "
                "(Heuristic: route name match; verify middleware is not in a separate file.)"
            ),
            evidence=Evidence(
                file_path=str(path.relative_to(root)),
                line=line_no,
                snippet=snippet,
            ),
            recommendation=(
                "Install express-rate-limit and apply it to auth routes: "
                "const limiter = rateLimit({ windowMs: 15*60*1000, max: 20 }); "
                "router.post('/login', limiter, loginHandler);"
            ),
        ))
    return findings


def _check_error_exposure(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _node_files(loader):
        content = loader.read_text(path)
        for i, line in enumerate(content.splitlines(), 1):
            if _ERR_STACK_IN_RES.search(line) or _ERR_SEND_RAW.search(line):
                findings.append(_make(
                    rule_id="EX-ERROR-001",
                    rule_name="Stack trace or raw error sent to client",
                    category="error_handling",
                    description=(
                        "A stack trace (err.stack) or raw error object is sent directly "
                        "in the HTTP response. This leaks internal file paths, library "
                        "versions, and application logic to users and aids attackers in "
                        "crafting targeted exploits."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=i,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Log errors server-side only (console.error / a logger). "
                        "Return a generic message to the client: "
                        "res.status(500).json({ error: 'Internal server error' })"
                    ),
                ))
    return findings


def _check_authz(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _node_files(loader):
        content = loader.read_text(path)
        if not _SENSITIVE_ROUTE.search(content):
            continue
        if _AUTH_MIDDLEWARE.search(content):
            continue  # auth middleware present in the same file

        for i, line in enumerate(content.splitlines(), 1):
            if _SENSITIVE_ROUTE.search(line):
                findings.append(_make(
                    rule_id="EX-AUTHZ-001",
                    rule_name="Sensitive route without auth middleware",
                    category="authorization",
                    description=(
                        "A route with a sensitive path (admin, dashboard, users, profile, etc.) "
                        "was found in a file that contains no recognizable authentication "
                        "middleware (isAuthenticated, verifyToken, passport, jwt.verify, etc.). "
                        "(Heuristic: checks file-level presence of auth middleware.)"
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=i,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Add authentication middleware to all sensitive routes: "
                        "router.get('/admin', verifyToken, adminHandler)"
                    ),
                ))
                break  # one finding per file
    return findings


def _check_json_limit(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _node_files(loader):
        content = loader.read_text(path)
        for i, line in enumerate(content.splitlines(), 1):
            if _JSON_NO_LIMIT.search(line) and not _JSON_WITH_LIMIT.search(line):
                findings.append(_make(
                    rule_id="EX-JSON-001",
                    rule_name="JSON body parser has no size limit",
                    category="denial_of_service",
                    description=(
                        "express.json() or bodyParser.json() is configured without a size limit. "
                        "An attacker can send arbitrarily large request bodies, exhausting "
                        "server memory and causing denial of service."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=i,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Set an explicit body size limit: "
                        "app.use(express.json({ limit: '10kb' }))"
                    ),
                ))
    return findings


# ── Public entry point ────────────────────────────────────────────────────────

def run_express_rules(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_helmet(root, loader))
    findings.extend(_check_cors(root, loader))
    findings.extend(_check_cookies(root, loader))
    findings.extend(_check_rate_limit(root, loader))
    findings.extend(_check_error_exposure(root, loader))
    findings.extend(_check_authz(root, loader))
    findings.extend(_check_json_limit(root, loader))
    return findings
