from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Evidence:
    file_path: str
    line: int | None = None
    snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "snippet": self.snippet,
        }


@dataclass(slots=True)
class RiskFactors:
    """E=Exploitability, I=Impact, D=Detectability, P=Prevalence (each 1–5)."""

    E: int
    I: int
    D: int
    P: int

    def to_dict(self) -> dict[str, Any]:
        return {"E": self.E, "I": self.I, "D": self.D, "P": self.P}


@dataclass(slots=True)
class Finding:
    rule_id: str
    rule_name: str
    category: str
    description: str
    evidence: Evidence
    recommendation: str
    risk_factors: RiskFactors
    risk_score: float
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence.to_dict(),
            "recommendation": self.recommendation,
            "risk_factors": self.risk_factors.to_dict(),
            "risk_score": self.risk_score,
            "severity": self.severity,
        }


@dataclass(slots=True)
class ScanReport:
    project_name: str
    framework: str = "unknown"
    scanned_files_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @classmethod
    def new(cls, target: Path) -> "ScanReport":
        return cls(project_name=target.resolve().name)

    def to_dict(self) -> dict[str, Any]:
        counts_by_severity: dict[str, int] = {}
        counts_by_category: dict[str, int] = {}
        for f in self.findings:
            counts_by_severity[f.severity] = counts_by_severity.get(f.severity, 0) + 1
            counts_by_category[f.category] = counts_by_category.get(f.category, 0) + 1
        return {
            "project_name": self.project_name,
            "framework": self.framework,
            "scanned_files_count": self.scanned_files_count,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total_findings": len(self.findings),
                "counts_by_severity": counts_by_severity,
                "counts_by_category": counts_by_category,
            },
            "errors": self.errors,
        }
