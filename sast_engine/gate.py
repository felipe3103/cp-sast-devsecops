"""Security Gate: decide se o pipeline deve ser bloqueado."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import Confidence, Finding, Severity


@dataclass
class GatePolicy:
    fail_on: Severity = Severity.HIGH          # severidade mínima que bloqueia
    min_confidence: Confidence = Confidence.MEDIUM
    max_findings: int | None = None            # limite opcional de achados totais
    baseline: set[str] | None = None           # fingerprints já conhecidos (dívida aceita)

    @staticmethod
    def load_baseline(path: str | Path) -> set[str]:
        data = json.loads(Path(path).read_text())
        return {f["fingerprint"] for f in data.get("findings", []) if "fingerprint" in f}


def evaluate(findings: list[Finding], policy: GatePolicy) -> dict:
    """Retorna o veredito do gate. Achados do baseline e descartados pela IA não bloqueiam."""
    considered = [
        f for f in findings
        if not f.extra.get("ai_suppressed")
        and (policy.baseline is None or f.fingerprint not in policy.baseline)
    ]
    blocking = [
        f for f in considered
        if f.severity >= policy.fail_on and f.confidence >= policy.min_confidence
    ]
    failed = bool(blocking)
    reason = (
        f"{len(blocking)} achado(s) com severidade >= {policy.fail_on.name} e confiança >= {policy.min_confidence.name}"
        if failed else f"nenhum achado novo com severidade >= {policy.fail_on.name}"
    )
    if policy.max_findings is not None and len(considered) > policy.max_findings:
        failed = True
        reason += f"; total de {len(considered)} achados excede o limite de {policy.max_findings}"
    return {
        "failed": failed,
        "reason": reason,
        "fail_on": policy.fail_on.name,
        "blocking": [f"{f.rule_id} {f.file}:{f.line}" for f in blocking],
        "new_findings": len(considered),
        "baseline_size": len(policy.baseline or ()),
    }
