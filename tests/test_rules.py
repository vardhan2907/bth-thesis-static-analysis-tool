"""Per-rule unit tests — one positive (fires) and one negative (clean) per rule."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner.file_loader import FileLoader
from scanner.rules.django_rules import run_django_rules
from scanner.rules.express_rules import run_express_rules


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_project(files: dict[str, str]) -> tuple[Path, FileLoader]:
    """Write files into a fresh temp dir and return (root, loader).

    The temp dir is NOT automatically cleaned up — callers must manage it.
    Use inside a tempfile.TemporaryDirectory() context.
    """
    raise NotImplementedError  # see _scan_* helpers below


def _scan_django(files: dict[str, str]) -> list[str]:
    """Create a temp project, run Django rules, return list of fired rule_ids."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, content in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        loader = FileLoader(root)
        return [f.rule_id for f in run_django_rules(root, loader)]


def _scan_express(files: dict[str, str]) -> list[str]:
    """Create a temp project, run Express rules, return list of fired rule_ids."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, content in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        loader = FileLoader(root)
        return [f.rule_id for f in run_express_rules(root, loader)]


# ── Django rule tests ─────────────────────────────────────────────────────────

class TestDjangoRules(unittest.TestCase):

    # DJ-DEBUG-001
    def test_debug_fires(self) -> None:
        ids = _scan_django({"settings.py": "DEBUG = True\n"})
        self.assertIn("DJ-DEBUG-001", ids)

    def test_debug_clean(self) -> None:
        ids = _scan_django({"settings.py": "DEBUG = False\n"})
        self.assertNotIn("DJ-DEBUG-001", ids)

    # DJ-SECRET-001
    def test_secret_key_fires(self) -> None:
        ids = _scan_django({"settings.py": "SECRET_KEY = 'django-insecure-abc123xyz'\n"})
        self.assertIn("DJ-SECRET-001", ids)

    def test_secret_key_clean_env_var(self) -> None:
        ids = _scan_django({"settings.py": "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\n"})
        self.assertNotIn("DJ-SECRET-001", ids)

    def test_secret_key_clean_getenv(self) -> None:
        ids = _scan_django({"settings.py": "SECRET_KEY = os.getenv('SECRET_KEY')\n"})
        self.assertNotIn("DJ-SECRET-001", ids)

    # DJ-HOSTS-001
    def test_allowed_hosts_wildcard_fires(self) -> None:
        ids = _scan_django({"settings.py": "ALLOWED_HOSTS = ['*']\n"})
        self.assertIn("DJ-HOSTS-001", ids)

    def test_allowed_hosts_empty_fires(self) -> None:
        ids = _scan_django({"settings.py": "ALLOWED_HOSTS = []\n"})
        self.assertIn("DJ-HOSTS-001", ids)

    def test_allowed_hosts_clean(self) -> None:
        ids = _scan_django({"settings.py": "ALLOWED_HOSTS = ['example.com']\n"})
        self.assertNotIn("DJ-HOSTS-001", ids)

    # DJ-COOKIE-001
    def test_cookie_secure_false_fires(self) -> None:
        ids = _scan_django({"settings.py": "SESSION_COOKIE_SECURE = False\n"})
        self.assertIn("DJ-COOKIE-001", ids)

    def test_cookie_secure_missing_fires(self) -> None:
        # Django's default is False — absence should still be flagged
        ids = _scan_django({"settings.py": "DEBUG = False\n"})
        self.assertIn("DJ-COOKIE-001", ids)

    def test_cookie_secure_clean(self) -> None:
        ids = _scan_django({"settings.py": "SESSION_COOKIE_SECURE = True\n"})
        self.assertNotIn("DJ-COOKIE-001", ids)

    # DJ-COOKIE-002
    def test_cookie_httponly_false_fires(self) -> None:
        ids = _scan_django({"settings.py": "SESSION_COOKIE_HTTPONLY = False\n"})
        self.assertIn("DJ-COOKIE-002", ids)

    def test_cookie_httponly_clean_explicit_true(self) -> None:
        ids = _scan_django({"settings.py": "SESSION_COOKIE_HTTPONLY = True\n"})
        self.assertNotIn("DJ-COOKIE-002", ids)

    def test_cookie_httponly_clean_absent(self) -> None:
        # Django defaults to True — absence is safe and should not be flagged
        ids = _scan_django({"settings.py": "DEBUG = False\n"})
        self.assertNotIn("DJ-COOKIE-002", ids)

    # DJ-CSRF-001
    def test_csrf_exempt_fires(self) -> None:
        ids = _scan_django({
            "settings.py": "",
            "views.py": "@csrf_exempt\ndef my_view(request): pass\n",
        })
        self.assertIn("DJ-CSRF-001", ids)

    def test_csrf_exempt_clean(self) -> None:
        ids = _scan_django({
            "settings.py": "",
            "views.py": "def my_view(request): pass\n",
        })
        self.assertNotIn("DJ-CSRF-001", ids)

    # DJ-ERROR-001 — DEBUG_PROPAGATE_EXCEPTIONS
    def test_error_propagate_fires(self) -> None:
        ids = _scan_django({"settings.py": "DEBUG_PROPAGATE_EXCEPTIONS = True\n"})
        self.assertIn("DJ-ERROR-001", ids)

    def test_error_propagate_clean(self) -> None:
        ids = _scan_django({"settings.py": "DEBUG_PROPAGATE_EXCEPTIONS = False\n"})
        self.assertNotIn("DJ-ERROR-001", ids)

    # DJ-ERROR-001 — traceback.format_exc() in view code
    def test_error_traceback_fires(self) -> None:
        ids = _scan_django({
            "settings.py": "",
            "views.py": "import traceback\nmsg = traceback.format_exc()\n",
        })
        self.assertIn("DJ-ERROR-001", ids)

    def test_error_traceback_clean(self) -> None:
        ids = _scan_django({
            "settings.py": "",
            "views.py": "import logging\nlogger = logging.getLogger(__name__)\n",
        })
        self.assertNotIn("DJ-ERROR-001", ids)

    # DJ-ERROR-001 — traceback in settings files must NOT fire (settings are excluded)
    def test_error_traceback_skipped_in_settings(self) -> None:
        ids = _scan_django({"settings.py": "import traceback\ntraceback.format_exc()\n"})
        # Should not fire for traceback in a settings file
        tb_findings = [i for i in ids if i == "DJ-ERROR-001"]
        # The propagate check won't fire and settings are excluded from traceback check
        self.assertEqual(tb_findings, [])


# ── Express rule tests ────────────────────────────────────────────────────────

class TestExpressRules(unittest.TestCase):

    # EX-HELMET-001
    def test_helmet_fires(self) -> None:
        ids = _scan_express({"app.js": "const express = require('express');\n"})
        self.assertIn("EX-HELMET-001", ids)

    def test_helmet_clean(self) -> None:
        ids = _scan_express({"app.js": "app.use(helmet());\n"})
        self.assertNotIn("EX-HELMET-001", ids)

    # EX-CORS-001
    def test_cors_wildcard_and_credentials_fires(self) -> None:
        code = "app.use(cors({ origin: '*', credentials: true }));\n"
        ids = _scan_express({"app.js": code})
        self.assertIn("EX-CORS-001", ids)

    def test_cors_wildcard_without_credentials_clean(self) -> None:
        # origin: '*' alone (no credentials) is not flagged by this rule
        ids = _scan_express({"app.js": "app.use(cors({ origin: '*' }));\n"})
        self.assertNotIn("EX-CORS-001", ids)

    def test_cors_explicit_origin_with_credentials_clean(self) -> None:
        code = "app.use(cors({ origin: 'https://example.com', credentials: true }));\n"
        ids = _scan_express({"app.js": code})
        self.assertNotIn("EX-CORS-001", ids)

    # EX-COOKIE-001
    def test_cookie_missing_flags_fires(self) -> None:
        ids = _scan_express({"app.js": "res.cookie('session', token);\n"})
        self.assertIn("EX-COOKIE-001", ids)

    def test_cookie_all_flags_clean(self) -> None:
        code = "res.cookie('s', v, { httpOnly: true, secure: true, sameSite: 'Strict' });\n"
        ids = _scan_express({"app.js": code})
        self.assertNotIn("EX-COOKIE-001", ids)

    def test_cookie_no_res_cookie_call_clean(self) -> None:
        ids = _scan_express({"app.js": "res.json({ ok: true });\n"})
        self.assertNotIn("EX-COOKIE-001", ids)

    # EX-RATE-001
    def test_rate_limit_fires_on_auth_route(self) -> None:
        ids = _scan_express({"routes.js": "router.post('/login', loginHandler);\n"})
        self.assertIn("EX-RATE-001", ids)

    def test_rate_limit_clean_when_present(self) -> None:
        code = (
            "const rateLimit = require('express-rate-limit');\n"
            "router.post('/login', rateLimit({ max: 5 }), loginHandler);\n"
        )
        ids = _scan_express({"routes.js": code})
        self.assertNotIn("EX-RATE-001", ids)

    def test_rate_limit_clean_no_auth_routes(self) -> None:
        ids = _scan_express({"app.js": "app.get('/products', listProducts);\n"})
        self.assertNotIn("EX-RATE-001", ids)

    # EX-ERROR-001
    def test_error_stack_in_response_fires(self) -> None:
        code = "app.use((err, req, res, next) => { res.send(err.stack); });\n"
        ids = _scan_express({"app.js": code})
        self.assertIn("EX-ERROR-001", ids)

    def test_error_raw_err_send_fires(self) -> None:
        ids = _scan_express({"app.js": "res.send(err);\n"})
        self.assertIn("EX-ERROR-001", ids)

    def test_error_generic_response_clean(self) -> None:
        code = "app.use((err, req, res, next) => { res.status(500).json({ error: 'oops' }); });\n"
        ids = _scan_express({"app.js": code})
        self.assertNotIn("EX-ERROR-001", ids)

    # EX-AUTHZ-001
    def test_authz_sensitive_route_no_middleware_fires(self) -> None:
        ids = _scan_express({"app.js": "app.get('/admin/dashboard', adminHandler);\n"})
        self.assertIn("EX-AUTHZ-001", ids)

    def test_authz_sensitive_route_with_auth_clean(self) -> None:
        code = "app.get('/admin/dashboard', verifyToken, adminHandler);\n"
        ids = _scan_express({"app.js": code})
        self.assertNotIn("EX-AUTHZ-001", ids)

    def test_authz_non_sensitive_route_clean(self) -> None:
        ids = _scan_express({"app.js": "app.get('/health', healthCheck);\n"})
        self.assertNotIn("EX-AUTHZ-001", ids)

    # EX-JSON-001
    def test_json_no_limit_fires(self) -> None:
        ids = _scan_express({"app.js": "app.use(express.json());\n"})
        self.assertIn("EX-JSON-001", ids)

    def test_json_empty_options_fires(self) -> None:
        ids = _scan_express({"app.js": "app.use(express.json({}));\n"})
        self.assertIn("EX-JSON-001", ids)

    def test_json_with_limit_clean(self) -> None:
        ids = _scan_express({"app.js": "app.use(express.json({ limit: '10kb' }));\n"})
        self.assertNotIn("EX-JSON-001", ids)

    def test_body_parser_with_limit_clean(self) -> None:
        ids = _scan_express({"app.js": "app.use(bodyParser.json({ limit: '1mb' }));\n"})
        self.assertNotIn("EX-JSON-001", ids)


if __name__ == "__main__":
    unittest.main()
