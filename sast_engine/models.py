"""Modelos de dados compartilhados pelo motor SAST."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        return cls[str(value).strip().upper()]


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str | "Confidence") -> "Confidence":
        if isinstance(value, Confidence):
            return value
        return cls[str(value).strip().upper()]


@dataclass
class TraceStep:
    """Um passo do caminho de dados (fonte -> propagação -> sink) na taint analysis."""

    line: int
    description: str
    file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    file: str
    line: int
    column: int = 0
    end_line: int | None = None
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    cwe: str = ""
    owasp: str = ""
    snippet: str = ""
    engine: str = "sast-engine"
    language: str = "python"
    trace: list[TraceStep] = field(default_factory=list)
    remediation: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Identificador estável do achado (não depende do número da linha).

        Usa regra + arquivo + trecho normalizado, assim o mesmo problema continua
        com o mesmo id quando linhas são inseridas acima dele. Isso permite medir
        tendência e tempo de correção entre varreduras.
        """
        normalized = " ".join(self.snippet.split())
        raw = f"{self.rule_id}|{self.file}|{normalized}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    @property
    def risk_score(self) -> float:
        """Pontuação 0-10 combinando severidade e confiança."""
        base = {0: 0.5, 1: 2.5, 2: 5.0, 3: 7.5, 4: 9.5}[int(self.severity)]
        factor = {1: 0.7, 2: 0.85, 3: 1.0}[int(self.confidence)]
        return round(base * factor, 1)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["confidence"] = self.confidence.name
        data["trace"] = [t.to_dict() for t in self.trace]
        data["fingerprint"] = self.fingerprint
        data["risk_score"] = self.risk_score
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        data = dict(data)
        data.pop("fingerprint", None)
        data.pop("risk_score", None)
        data["severity"] = Severity.parse(data.get("severity", "MEDIUM"))
        data["confidence"] = Confidence.parse(data.get("confidence", "MEDIUM"))
        data["trace"] = [TraceStep(**t) for t in data.get("trace", [])]
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ParseError:
    file: str
    message: str
    line: int = 0


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    duration_ms: int = 0
    languages: dict[str, int] = field(default_factory=dict)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "files_scanned": self.files_scanned,
                "lines_scanned": self.lines_scanned,
                "duration_ms": self.duration_ms,
                "total_findings": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "languages": self.languages,
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": [asdict(e) for e in self.errors],
        }
