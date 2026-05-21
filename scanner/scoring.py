from __future__ import annotations

from .models import RiskFactors

# Per-rule E/I/D/P defaults (each 1–5).
# Formula: risk_score = (E + I + D + P) / 2  →  range 2.0–10.0
_RISK_TEMPLATES: dict[str, dict[str, int]] = {
    # Django
    "DJ-DEBUG-001":  {"E": 4, "I": 4, "D": 4, "P": 4},  # 8.0 High
    "DJ-SECRET-001": {"E": 5, "I": 5, "D": 3, "P": 3},  # 8.0 High
    "DJ-HOSTS-001":  {"E": 3, "I": 4, "D": 3, "P": 3},  # 6.5 High
    "DJ-COOKIE-001": {"E": 3, "I": 3, "D": 3, "P": 4},  # 6.5 High
    "DJ-COOKIE-002": {"E": 3, "I": 3, "D": 3, "P": 4},  # 6.5 High
    "DJ-CSRF-001":   {"E": 4, "I": 4, "D": 3, "P": 3},  # 7.0 High
    "DJ-ERROR-001":  {"E": 2, "I": 3, "D": 3, "P": 4},  # 6.0 High
    # Express
    "EX-HELMET-001": {"E": 3, "I": 3, "D": 4, "P": 4},  # 7.0 High
    "EX-CORS-001":   {"E": 4, "I": 4, "D": 3, "P": 3},  # 7.0 High
    "EX-COOKIE-001": {"E": 3, "I": 3, "D": 3, "P": 4},  # 6.5 High
    "EX-RATE-001":   {"E": 4, "I": 3, "D": 3, "P": 4},  # 7.0 High
    "EX-ERROR-001":  {"E": 2, "I": 3, "D": 3, "P": 4},  # 6.0 High
    "EX-AUTHZ-001":  {"E": 4, "I": 5, "D": 3, "P": 3},  # 7.5 High
    "EX-JSON-001":   {"E": 3, "I": 3, "D": 4, "P": 3},  # 6.5 High
}

_DEFAULT: dict[str, int] = {"E": 2, "I": 2, "D": 2, "P": 2}


def score_for_rule(rule_id: str) -> tuple[RiskFactors, float, str]:
    """Return (RiskFactors, risk_score, severity) for the given rule ID."""
    t = _RISK_TEMPLATES.get(rule_id, _DEFAULT)
    factors = RiskFactors(E=t["E"], I=t["I"], D=t["D"], P=t["P"])
    risk_score = compute_risk_score(factors)
    severity = compute_severity(risk_score)
    return factors, risk_score, severity


def compute_risk_score(factors: RiskFactors) -> float:
    """Compute a 0–10 risk score from E/I/D/P (each 1–5).

    Formula: (E + I + D + P) / 2
    Range: 2.0 (all 1s) to 10.0 (all 5s).
    """
    return round((factors.E + factors.I + factors.D + factors.P) / 2, 1)


def compute_severity(score: float) -> str:
    """Map a 0–10 risk score to a severity tier per SKILLS.md thresholds."""
    if score >= 7.6:
        return "Critical"
    if score >= 5.1:
        return "High"
    if score >= 2.6:
        return "Medium"
    return "Low"
