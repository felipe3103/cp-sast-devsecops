"""Integração com motores externos (Bandit e Semgrep).

Os resultados são normalizados para o mesmo modelo `Finding`, e o deduplicador
do scanner une achados iguais (mesmo arquivo, linha e CWE) vindos de motores
diferentes. Assim o relatório final mostra a visão consolidada.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import Confidence, Finding, Severity
from .rules.catalog import A02, A03, A05, A07, A08

BANDIT_SEVERITY = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}
SEMGREP_SEVERITY = {"INFO": Severity.LOW, "WARNING": Severity.MEDIUM, "ERROR": Severity.HIGH}
CWE_TO_OWASP = {
    "CWE-78": A03, "CWE-89": A03, "CWE-79": A03, "CWE-94": A03, "CWE-95": A03, "CWE-502": A08,
    "CWE-798": A07, "CWE-259": A07, "CWE-327": A02, "CWE-328": A02, "CWE-295": A02, "CWE-611": A05,
}

DEFAULT_SEMGREP_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep"


def _run(cmd: list[str], cwd: Path) -> dict | None:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None


def run_bandit(root: Path, exclude: list[str]) -> list[Finding]:
    exe = shutil.which("bandit")
    if not exe:
        return []
    exe = str(Path(exe).resolve())
    excludes = ",".join(f"./{e}" for e in exclude if "*" not in e)
    data = _run([exe, "-r", ".", "-f", "json", "-q", "-x", excludes], root)
    findings = []
    for item in (data or {}).get("results", []):
        cwe = f"CWE-{item.get('issue_cwe', {}).get('id', '')}".rstrip("-")
        findings.append(Finding(
            rule_id=f"BANDIT-{item['test_id']}",
            title=item["test_name"].replace("_", " ").capitalize(),
            message=item["issue_text"],
            file=str(Path(item["filename"]).as_posix()).removeprefix("./"),
            line=item["line_number"],
            severity=BANDIT_SEVERITY.get(item["issue_severity"], Severity.LOW),
            confidence=Confidence[item["issue_confidence"]],
            cwe=cwe if cwe != "CWE" else "",
            owasp=CWE_TO_OWASP.get(cwe, ""),
            snippet=item.get("code", "").strip(),
            engine="bandit",
        ))
    return findings


def run_semgrep(root: Path, config: str | None, exclude: list[str]) -> list[Finding]:
    exe = shutil.which("semgrep")
    if not exe:
        return []
    cmd = [str(Path(exe).resolve()), "scan", "--json", "--quiet", "--metrics=off", "--config", config or str(DEFAULT_SEMGREP_RULES)]
    for pattern in exclude:
        cmd += ["--exclude", pattern]
    data = _run(cmd + ["."], root)
    findings = []
    for item in (data or {}).get("results", []):
        meta = item.get("extra", {}).get("metadata", {})
        cwe_raw = meta.get("cwe", [""])
        cwe = (cwe_raw[0] if isinstance(cwe_raw, list) else cwe_raw).split(":")[0]
        findings.append(Finding(
            rule_id=f"SEMGREP-{item['check_id'].rsplit('.', 1)[-1]}",
            title=meta.get("title", item["check_id"].rsplit(".", 1)[-1]),
            message=item["extra"].get("message", ""),
            file=item["path"],
            line=item["start"]["line"],
            end_line=item["end"]["line"],
            severity=SEMGREP_SEVERITY.get(item["extra"].get("severity", "WARNING"), Severity.MEDIUM),
            confidence=Confidence.MEDIUM,
            cwe=cwe,
            owasp=CWE_TO_OWASP.get(cwe, ""),
            snippet=item["extra"].get("lines", "").strip(),
            engine="semgrep",
        ))
    return findings
