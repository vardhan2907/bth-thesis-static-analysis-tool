from __future__ import annotations

import re
from pathlib import Path

from ..file_loader import FileLoader
from ..models import Evidence, Finding
from ..scoring import score_for_rule

# ── Compiled patterns ─────────────────────────────────────────────────────────

_DEBUG_TRUE = re.compile(r"^\s*DEBUG\s*=\s*True\b", re.MULTILINE)

_SECRET_KEY_LITERAL = re.compile(r"""^\s*SECRET_KEY\s*=\s*['"].+['"]""", re.MULTILINE)
_SECRET_KEY_ENV_MARKERS = (
    "os.environ", "os.getenv", "env(", "environ[", "config(", "get_secret", "decouple",
)

_ALLOWED_HOSTS_STAR = re.compile(r"""ALLOWED_HOSTS\s*=\s*\[.*['"][*]['"].*\]""")
_ALLOWED_HOSTS_EMPTY = re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*\]")

_COOKIE_SECURE_FALSE = re.compile(r"^\s*SESSION_COOKIE_SECURE\s*=\s*False\b", re.MULTILINE)
_COOKIE_SECURE_ANY = re.compile(r"SESSION_COOKIE_SECURE")

_COOKIE_HTTPONLY_FALSE = re.compile(r"^\s*SESSION_COOKIE_HTTPONLY\s*=\s*False\b", re.MULTILINE)

_CSRF_EXEMPT = re.compile(r"@csrf_exempt")

_DEBUG_PROPAGATE = re.compile(r"^\s*DEBUG_PROPAGATE_EXCEPTIONS\s*=\s*True\b", re.MULTILINE)
_TRACEBACK_FORMAT_EXC = re.compile(r"traceback\.format_exc\s*\(\s*\)")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _settings_files(loader: FileLoader) -> list[Path]:
    return [
        p for p in loader.list_files()
        if p.suffix == ".py" and "settings" in p.name.lower()
    ]


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

def _check_debug(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _settings_files(loader):
        content = loader.read_text(path)
        for line_no, line in enumerate(content.splitlines(), 1):
            if _DEBUG_TRUE.search(line):
                findings.append(_make(
                    rule_id="DJ-DEBUG-001",
                    rule_name="DEBUG mode enabled",
                    category="security_misconfiguration",
                    description=(
                        "Django's DEBUG=True exposes full stack traces, local variables, "
                        "and settings to any user who triggers an error. "
                        "Must be False in production."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip(),
                    ),
                    recommendation="Set DEBUG = False for all production deployments.",
                ))
    return findings


def _check_secret_key(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _settings_files(loader):
        content = loader.read_text(path)
        for line_no, line in enumerate(content.splitlines(), 1):
            if _SECRET_KEY_LITERAL.search(line):
                if any(marker in line for marker in _SECRET_KEY_ENV_MARKERS):
                    continue
                findings.append(_make(
                    rule_id="DJ-SECRET-001",
                    rule_name="Hardcoded SECRET_KEY",
                    category="secrets_management",
                    description=(
                        "A literal string value is used as Django's SECRET_KEY. "
                        "If this file is committed to version control the secret is exposed. "
                        "SECRET_KEY must be loaded from an environment variable or secrets manager."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip()[:120],
                    ),
                    recommendation=(
                        "Load SECRET_KEY from the environment: "
                        "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']"
                    ),
                ))
    return findings


def _check_allowed_hosts(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in _settings_files(loader):
        content = loader.read_text(path)
        for line_no, line in enumerate(content.splitlines(), 1):
            if _ALLOWED_HOSTS_STAR.search(line):
                findings.append(_make(
                    rule_id="DJ-HOSTS-001",
                    rule_name="ALLOWED_HOSTS wildcard",
                    category="security_misconfiguration",
                    description=(
                        "ALLOWED_HOSTS = ['*'] accepts requests for any hostname, "
                        "enabling HTTP host header injection attacks in production."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Set ALLOWED_HOSTS to the explicit list of domains your app serves, "
                        "e.g. ALLOWED_HOSTS = ['example.com', 'www.example.com']."
                    ),
                ))
            elif _ALLOWED_HOSTS_EMPTY.search(line):
                findings.append(_make(
                    rule_id="DJ-HOSTS-001",
                    rule_name="ALLOWED_HOSTS empty",
                    category="security_misconfiguration",
                    description=(
                        "ALLOWED_HOSTS = [] is only safe while DEBUG=True. "
                        "In production with DEBUG=False it rejects all requests and is a "
                        "sign the value has not been configured for deployment."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Set ALLOWED_HOSTS to your explicit domain list before deploying."
                    ),
                ))
    return findings


def _check_session_cookie_secure(root: Path, loader: FileLoader) -> list[Finding]:
    settings = _settings_files(loader)
    if not settings:
        return []

    findings: list[Finding] = []
    combined = "\n".join(loader.read_text(p) for p in settings)

    if not _COOKIE_SECURE_ANY.search(combined):
        # Missing entirely — Django's default is False
        primary = settings[0]
        findings.append(_make(
            rule_id="DJ-COOKIE-001",
            rule_name="SESSION_COOKIE_SECURE not set",
            category="session_security",
            description=(
                "SESSION_COOKIE_SECURE is not present in any settings file. "
                "Django defaults to False, which allows the session cookie to be "
                "transmitted over plain HTTP, enabling session hijacking."
            ),
            evidence=Evidence(
                file_path=str(primary.relative_to(root)),
                snippet="SESSION_COOKIE_SECURE not found in settings.",
            ),
            recommendation="Add SESSION_COOKIE_SECURE = True to your production settings.",
        ))
    else:
        for path in settings:
            content = loader.read_text(path)
            for line_no, line in enumerate(content.splitlines(), 1):
                if _COOKIE_SECURE_FALSE.search(line):
                    findings.append(_make(
                        rule_id="DJ-COOKIE-001",
                        rule_name="SESSION_COOKIE_SECURE disabled",
                        category="session_security",
                        description=(
                            "SESSION_COOKIE_SECURE = False explicitly allows the session cookie "
                            "to be sent over unencrypted HTTP, enabling session hijacking on "
                            "non-HTTPS connections."
                        ),
                        evidence=Evidence(
                            file_path=str(path.relative_to(root)),
                            line=line_no,
                            snippet=line.strip(),
                        ),
                        recommendation="Set SESSION_COOKIE_SECURE = True in production settings.",
                    ))
    return findings


def _check_session_cookie_httponly(root: Path, loader: FileLoader) -> list[Finding]:
    settings = _settings_files(loader)
    if not settings:
        return []

    # Django's default for SESSION_COOKIE_HTTPONLY is True, so only flag explicit False.
    findings: list[Finding] = []
    for path in settings:
        content = loader.read_text(path)
        for line_no, line in enumerate(content.splitlines(), 1):
            if _COOKIE_HTTPONLY_FALSE.search(line):
                findings.append(_make(
                    rule_id="DJ-COOKIE-002",
                    rule_name="SESSION_COOKIE_HTTPONLY disabled",
                    category="session_security",
                    description=(
                        "SESSION_COOKIE_HTTPONLY = False explicitly removes the HttpOnly flag, "
                        "making the session cookie readable by JavaScript. "
                        "Any XSS vulnerability on the site can then steal session tokens."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip(),
                    ),
                    recommendation="Remove this line or set SESSION_COOKIE_HTTPONLY = True.",
                ))
    return findings


def _check_csrf_exempt(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    for path in loader.list_files():
        if path.suffix != ".py":
            continue
        content = loader.read_text(path)
        for line_no, line in enumerate(content.splitlines(), 1):
            if _CSRF_EXEMPT.search(line):
                findings.append(_make(
                    rule_id="DJ-CSRF-001",
                    rule_name="@csrf_exempt decorator used",
                    category="csrf_protection",
                    description=(
                        "@csrf_exempt disables Django's CSRF protection for this view. "
                        "State-changing endpoints (POST/PUT/DELETE) without CSRF protection "
                        "are vulnerable to cross-site request forgery. "
                        "(Heuristic: review whether this exemption is intentional and safe.)"
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Remove @csrf_exempt and use Django's CSRF middleware. "
                        "For REST APIs, use token-based auth (DRF SessionAuthentication or JWT) "
                        "instead of exempting CSRF."
                    ),
                ))
    return findings


def _check_error_leakage(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []

    # Check 1: DEBUG_PROPAGATE_EXCEPTIONS = True in settings
    for path in _settings_files(loader):
        content = loader.read_text(path)
        for line_no, line in enumerate(content.splitlines(), 1):
            if _DEBUG_PROPAGATE.search(line):
                findings.append(_make(
                    rule_id="DJ-ERROR-001",
                    rule_name="DEBUG_PROPAGATE_EXCEPTIONS enabled",
                    category="error_handling",
                    description=(
                        "DEBUG_PROPAGATE_EXCEPTIONS = True causes Django to re-raise exceptions "
                        "instead of returning a generic 500 response. In some WSGI/ASGI setups "
                        "this exposes raw tracebacks to clients."
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Remove or set DEBUG_PROPAGATE_EXCEPTIONS = False in production."
                    ),
                ))

    # Check 2: traceback.format_exc() in non-settings Python files (heuristic)
    for path in loader.list_files():
        if path.suffix != ".py" or "settings" in path.name.lower():
            continue
        content = loader.read_text(path)
        for line_no, line in enumerate(content.splitlines(), 1):
            if _TRACEBACK_FORMAT_EXC.search(line):
                findings.append(_make(
                    rule_id="DJ-ERROR-001",
                    rule_name="traceback.format_exc() in application code",
                    category="error_handling",
                    description=(
                        "traceback.format_exc() captures the full stack trace as a string. "
                        "If this value is included in an HTTP response it leaks internal "
                        "file paths, library versions, and application logic to users. "
                        "(Heuristic: verify the result is only written to logs, not responses.)"
                    ),
                    evidence=Evidence(
                        file_path=str(path.relative_to(root)),
                        line=line_no,
                        snippet=line.strip(),
                    ),
                    recommendation=(
                        "Log the traceback server-side only (e.g. logger.exception(...)). "
                        "Return a generic error message to the client."
                    ),
                ))
    return findings


# ── Public entry point ────────────────────────────────────────────────────────

def run_django_rules(root: Path, loader: FileLoader) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_debug(root, loader))
    findings.extend(_check_secret_key(root, loader))
    findings.extend(_check_allowed_hosts(root, loader))
    findings.extend(_check_session_cookie_secure(root, loader))
    findings.extend(_check_session_cookie_httponly(root, loader))
    findings.extend(_check_csrf_exempt(root, loader))
    findings.extend(_check_error_leakage(root, loader))
    return findings
