"""Formatos de saída: texto (terminal), JSON, SARIF 2.1.0 e Markdown."""
from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .models import Finding, ScanResult, Severity
from .rules.catalog import CATALOG

SEVERITY_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
SARIF_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "1.0"}


def to_json(result: ScanResult, gate: dict | None = None) -> str:
    data = result.to_dict()
    if gate is not None:
        data["gate"] = gate
    return json.dumps(data, indent=2, ensure_ascii=False)


def to_text(result: ScanResult, gate: dict | None = None) -> str:
    out = []
    for f in result.findings:
        out.append(f"{SEVERITY_ICON[f.severity.name]} [{f.severity.name}] {f.rule_id} {f.title} ({f.cwe})")
        out.append(f"   {f.file}:{f.line}  {f.message}")
        if f.snippet:
            out.append("   │ " + f.snippet.splitlines()[0].strip())
        if f.trace:
            out.append("   ↳ fluxo: " + " → ".join(
                f"{'' if s.file in ('', f.file) else s.file + ':'}L{s.line} {s.description}" for s in f.trace
            ))
        out.append("")
    s = result.to_dict()["summary"]
    counts = ", ".join(f"{k}: {v}" for k, v in s["by_severity"].items() if v)
    out.append(f"Arquivos: {s['files_scanned']} | Linhas: {s['lines_scanned']} | Tempo: {s['duration_ms']} ms")
    out.append(f"Achados: {s['total_findings']} ({counts or 'nenhum'})")
    for err in result.errors:
        out.append(f"⚠ erro de parsing em {err.file}:{err.line} - {err.message}")
    if gate:
        out.append(("❌ SECURITY GATE REPROVADO: " if gate["failed"] else "✅ Security Gate aprovado: ") + gate["reason"])
    return "\n".join(out)


def to_markdown(result: ScanResult, gate: dict | None = None, limit: int = 30) -> str:
    s = result.to_dict()["summary"]
    lines = ["## 🔐 Relatório SAST", ""]
    if gate:
        status = "❌ **REPROVADO**" if gate["failed"] else "✅ **APROVADO**"
        lines += [f"**Security Gate:** {status} — {gate['reason']}", ""]
    lines += ["| Severidade | Qtd |", "|---|---|"]
    lines += [f"| {SEVERITY_ICON[k]} {k} | {v} |" for k, v in s["by_severity"].items()]
    lines += ["", f"Arquivos analisados: **{s['files_scanned']}** · Linhas: **{s['lines_scanned']}** · Tempo: **{s['duration_ms']} ms**", ""]
    top_files = Counter(f.file for f in result.findings).most_common(5)
    if top_files:
        lines += ["### Arquivos mais críticos", "", "| Arquivo | Achados |", "|---|---|"]
        lines += [f"| `{name}` | {n} |" for name, n in top_files]
        lines.append("")
    if result.findings:
        lines += ["### Achados", "", "| Sev. | Regra | Local | Descrição |", "|---|---|---|---|"]
        for f in result.findings[:limit]:
            lines.append(f"| {SEVERITY_ICON[f.severity.name]} {f.severity.name} | {f.rule_id} ({f.cwe}) | `{f.file}:{f.line}` | {f.message} |")
        if len(result.findings) > limit:
            lines.append(f"\n… e mais {len(result.findings) - limit} achados (veja o SARIF/dashboard).")
    return "\n".join(lines)


def to_sarif(result: ScanResult) -> str:
    rules_used: dict[str, Finding] = {}
    for f in result.findings:
        rules_used.setdefault(f.rule_id, f)
    rules = []
    for rule_id, sample in rules_used.items():
        meta = CATALOG.get(rule_id)
        tags = ["security"] + [t for t in (sample.cwe, sample.owasp.split(" - ")[0] if sample.owasp else "") if t]
        rules.append({
            "id": rule_id,
            "name": sample.title,
            "shortDescription": {"text": sample.title},
            "fullDescription": {"text": meta.description if meta else sample.message},
            "help": {"text": meta.remediation if meta else sample.remediation or sample.message},
            "properties": {"tags": tags, "security-severity": SARIF_SCORE[sample.severity]},
        })
    results = []
    for f in result.findings:
        entry = {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line, "startColumn": f.column + 1, "endLine": f.end_line or f.line},
                }
            }],
            "partialFingerprints": {"sastFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity.name, "confidence": f.confidence.name, "engine": f.engine},
        }
        if f.trace:
            entry["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {
                    "physicalLocation": {"artifactLocation": {"uri": s.file or f.file}, "region": {"startLine": s.line}},
                    "message": {"text": s.description},
                }} for s in f.trace
            ]}]}]
        results.append(entry)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SentinelaSAST", "version": __version__,
                                "informationUri": "https://github.com/", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


GITLAB_SEVERITY = {Severity.CRITICAL: "Critical", Severity.HIGH: "High", Severity.MEDIUM: "Medium", Severity.LOW: "Low", Severity.INFO: "Info"}


def to_gitlab_sast(result: ScanResult) -> str:
    """Relatório no formato GitLab SAST (schema 15.x): aparece no widget de segurança do MR."""
    from datetime import datetime, timedelta, timezone

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(milliseconds=result.duration_ms)
    fmt = "%Y-%m-%dT%H:%M:%S"
    tool = {"id": "sentinela-sast", "name": "SentinelaSAST", "version": __version__, "vendor": {"name": "SentinelaSAST"}}
    vulnerabilities = []
    for f in result.findings:
        identifiers = [{"type": "sentinela_rule", "name": f.rule_id, "value": f.rule_id}]
        if f.cwe.startswith("CWE-"):
            n = f.cwe.split("-", 1)[1]
            identifiers.append({"type": "cwe", "name": f.cwe, "value": n, "url": f"https://cwe.mitre.org/data/definitions/{n}.html"})
        vulnerabilities.append({
            "id": f.fingerprint,
            "category": "sast",
            "name": f.title,
            "message": f.message,
            "description": f.message + (f"\n\nRemediação: {f.remediation}" if f.remediation else ""),
            "severity": GITLAB_SEVERITY[f.severity],
            "scanner": {"id": tool["id"], "name": tool["name"]},
            "location": {"file": f.file, "start_line": f.line, "end_line": f.end_line or f.line},
            "identifiers": identifiers,
        })
    report = {
        "version": "15.0.7",
        "vulnerabilities": vulnerabilities,
        "scan": {
            "analyzer": tool, "scanner": tool, "type": "sast", "status": "success",
            "start_time": start.strftime(fmt), "end_time": end.strftime(fmt),
        },
    }
    return json.dumps(report, indent=2, ensure_ascii=False)
