"""Regras de negócio: ingestão segura de código, execução da varredura, IA e métricas."""
from __future__ import annotations

import io
import os
import re
import subprocess
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from sast_engine.ai import AITriage
from sast_engine.gate import GatePolicy, evaluate
from sast_engine.models import Finding, ScanResult, Severity
from sast_engine.scanner import LANG_BY_EXT, ScanConfig, collect_files, scan_sources

from .config import settings
from .db import FindingRow, Project, Scan, ScanFile, utcnow

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class IngestError(ValueError):
    pass


# ============================================================ ingestão
def extract_zip(data: bytes) -> dict[str, str]:
    """Extrai somente arquivos suportados, em memória, com proteção contra zip slip/zip bomb."""
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise IngestError(f"arquivo maior que {settings.max_upload_mb} MB")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("arquivo .zip inválido") from exc
    files: dict[str, str] = {}
    total = 0
    config = ScanConfig()
    for info in archive.infolist():
        if info.is_dir():
            continue
        name = PurePosixPath(info.filename.replace("\\", "/"))
        if name.is_absolute() or ".." in name.parts:
            raise IngestError(f"caminho inseguro no zip: {info.filename}")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            continue  # symlink
        if name.suffix not in LANG_BY_EXT or any(p in config.exclude for p in name.parts):
            continue
        total += info.file_size
        if total > settings.max_upload_mb * 4 * 1024 * 1024 or len(files) >= settings.max_files:
            raise IngestError("conteúdo descompactado excede o limite (possível zip bomb)")
        files[str(name)] = archive.read(info).decode("utf-8", errors="replace")
    if not files:
        raise IngestError("nenhum arquivo .py/.js encontrado no zip")
    return _strip_common_root(files)


def _strip_common_root(files: dict[str, str]) -> dict[str, str]:
    roots = {p.split("/", 1)[0] for p in files}
    if len(roots) == 1 and all("/" in p for p in files):
        return {p.split("/", 1)[1]: c for p, c in files.items()}
    return files


GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.\-]+/[\w.\-]+/[\w.\-]+?(\.git)?/?$")


def clone_repository(repo_url: str, ref: str | None = None) -> dict[str, str]:
    """Clona repositório PÚBLICO de host autorizado (ética: só código aberto/autorizado)."""
    parsed = urlparse(repo_url)
    if not GIT_URL_RE.match(repo_url) or parsed.hostname not in settings.allowed_git_hosts:
        raise IngestError(f"URL não permitida. Hosts aceitos: {', '.join(settings.allowed_git_hosts)}")
    if ref and not re.fullmatch(r"[\w.\-/]{1,100}", ref):
        raise IngestError("ref inválida")
    with tempfile.TemporaryDirectory() as tmp:
        cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags"]
        if ref:
            cmd += ["--branch", ref]
        cmd += ["--", repo_url, tmp]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env, check=False)
        if proc.returncode != 0:
            raise IngestError(f"falha ao clonar: {proc.stderr.strip()[:300]}")
        files = collect_files(Path(tmp), ScanConfig())
    if len(files) > settings.max_files:
        raise IngestError("repositório excede o limite de arquivos")
    return files


# ============================================================ varredura
def get_or_create_project(session: Session, name: str) -> Project:
    name = (name or "default").strip()[:200]
    project = session.scalar(select(Project).where(Project.name == name))
    if project is None:
        project = Project(name=name)
        session.add(project)
        session.flush()
    return project


def persist_result(session: Session, scan: Scan, result: ScanResult, files: dict[str, str] | None, gate: dict | None) -> None:
    scan.files_scanned = result.files_scanned
    scan.lines_scanned = result.lines_scanned
    scan.duration_ms = result.duration_ms
    scan.counts = result.counts_by_severity()
    if gate is not None:
        scan.gate_failed = gate["failed"]
        scan.gate_reason = gate["reason"]
    for f in result.findings:
        data = f.to_dict()
        session.add(FindingRow(
            scan_id=scan.id, fingerprint=data["fingerprint"], rule_id=f.rule_id, title=f.title,
            message=f.message, file=f.file, line=f.line, end_line=f.end_line, severity=f.severity.name,
            confidence=f.confidence.name, cwe=f.cwe, owasp=f.owasp, snippet=f.snippet, engine=f.engine,
            language=f.language, trace=data["trace"], remediation=f.remediation, risk_score=f.risk_score,
            ai=f.extra.get("ai"), ai_status="done" if f.extra.get("ai") else "none",
            status="false_positive" if f.extra.get("ai_suppressed") else "open",
        ))
    if files:
        for path in {f.file for f in result.findings}:
            if path in files:
                session.add(ScanFile(scan_id=scan.id, path=path, content=files[path]))
    scan.status = "completed"
    scan.finished_at = utcnow()


def execute_scan(session: Session, scan: Scan, files: dict[str, str]) -> None:
    scan.status = "running"
    session.commit()
    result = scan_sources(files, ScanConfig())
    gate = evaluate(result.findings, GatePolicy())
    persist_result(session, scan, result, files, gate)
    session.commit()


def row_to_finding(row: FindingRow) -> Finding:
    return Finding.from_dict({
        "rule_id": row.rule_id, "title": row.title, "message": row.message, "file": row.file,
        "line": row.line, "end_line": row.end_line, "severity": row.severity, "confidence": row.confidence,
        "cwe": row.cwe, "owasp": row.owasp, "snippet": row.snippet, "engine": row.engine,
        "language": row.language, "trace": row.trace or [], "remediation": row.remediation,
        "extra": {"ai": row.ai} if row.ai else {},
    })


def scan_result_from_db(scan: Scan) -> ScanResult:
    result = ScanResult(files_scanned=scan.files_scanned, lines_scanned=scan.lines_scanned, duration_ms=scan.duration_ms)
    result.findings = [row_to_finding(r) for r in scan.findings if r.status == "open"]
    return result


# ================================================================== IA
def triage_finding(session: Session, row: FindingRow, triage: AITriage | None = None) -> dict:
    triage = triage or AITriage()
    project_files = {f.path: f.content for f in session.scalars(select(ScanFile).where(ScanFile.scan_id == row.scan_id))}
    source = project_files.get(row.file, row.snippet)
    analysis = triage.analyze(row_to_finding(row), source, project_files)
    row.ai = analysis.to_dict()
    row.ai_status = "done"
    if analysis.source == "llm":
        row.severity = analysis.severity
        if analysis.suppressed:
            row.status = "false_positive"
    session.commit()
    return row.ai


def semantic_review_scan(session: Session, scan: Scan, triage: AITriage | None = None) -> int:
    triage = triage or AITriage()
    created = 0
    for file_row in scan.files:
        if not file_row.path.endswith(".py"):
            continue
        for f in triage.semantic_review(file_row.path, file_row.content):
            data = f.to_dict()
            session.add(FindingRow(
                scan_id=scan.id, fingerprint=data["fingerprint"], rule_id=f.rule_id, title=f.title,
                message=f.message, file=f.file, line=f.line, severity=f.severity.name,
                confidence=f.confidence.name, cwe=f.cwe, snippet=f.snippet, engine=f.engine,
                remediation=f.remediation, risk_score=f.risk_score, trace=[],
            ))
            created += 1
    session.commit()
    return created


# ============================================================= métricas
def finding_to_dict(row: FindingRow, with_ai: bool = True) -> dict:
    data = {
        "id": row.id, "scan_id": row.scan_id, "fingerprint": row.fingerprint, "rule_id": row.rule_id,
        "title": row.title, "message": row.message, "file": row.file, "line": row.line,
        "severity": row.severity, "confidence": row.confidence, "cwe": row.cwe, "owasp": row.owasp,
        "snippet": row.snippet, "engine": row.engine, "language": row.language, "trace": row.trace,
        "remediation": row.remediation, "risk_score": row.risk_score, "status": row.status,
        "ai_status": row.ai_status,
    }
    if with_ai:
        data["ai"] = row.ai
    return data


def scan_to_dict(scan: Scan) -> dict:
    return {
        "id": scan.id, "project": scan.project.name, "status": scan.status, "source": scan.source,
        "ref": scan.ref, "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "files_scanned": scan.files_scanned, "lines_scanned": scan.lines_scanned,
        "duration_ms": scan.duration_ms, "counts": scan.counts or {}, "gate_failed": scan.gate_failed,
        "gate_reason": scan.gate_reason, "error": scan.error,
    }


def compute_metrics(session: Session, project: str | None = None) -> dict:
    query = select(Scan).where(Scan.status == "completed").order_by(Scan.created_at)
    if project:
        query = query.join(Project).where(Project.name == project)
    scans = list(session.scalars(query))

    latest: dict[int, Scan] = {}
    for scan in scans:
        latest[scan.project_id] = scan  # ordenado por data: fica o mais recente
    current = [f for s in latest.values() for f in s.findings if f.status == "open"]

    severity = Counter(f.severity for f in current)
    files = Counter(f.file if len(latest) == 1 else f"{f.scan.project.name}/{f.file}" for f in current)
    files_sev: dict[str, Counter] = defaultdict(Counter)
    for f in current:
        key = f.file if len(latest) == 1 else f"{f.scan.project.name}/{f.file}"
        files_sev[key][f.severity] += 1
    owasp = Counter(f.owasp or "Não classificado" for f in current)
    cwe = Counter(f.cwe or "N/A" for f in current)
    engines = Counter(f.engine.split("/")[0] for f in current)

    # tendência: últimas 20 varreduras
    trend = [
        {"scan_id": s.id, "project": s.project.name, "date": s.created_at.isoformat(), "ref": s.ref,
         **{sev: (s.counts or {}).get(sev, 0) for sev in SEVERITIES},
         "gate_failed": s.gate_failed}
        for s in scans[-20:]
    ]

    # novos x corrigidos entre as duas últimas varreduras do projeto (por fingerprint)
    delta = {"new": 0, "fixed": 0}
    if project and len(scans) >= 2:
        prev = {f.fingerprint for f in scans[-2].findings}
        last = {f.fingerprint for f in scans[-1].findings}
        delta = {"new": len(last - prev), "fixed": len(prev - last)}

    all_current = [f for s in latest.values() for f in s.findings]
    triaged = [f for f in all_current if f.ai_status == "done"]
    ai_fp = [f for f in all_current if f.status == "false_positive" and f.ai and f.ai.get("suppressed")]

    return {
        "kpis": {
            "open_findings": len(current),
            "critical": severity.get("CRITICAL", 0),
            "high": severity.get("HIGH", 0),
            "risk_score": round(sum(f.risk_score for f in current), 1),
            "projects": len(latest),
            "scans": len(scans),
            "files_scanned": sum(s.files_scanned for s in latest.values()),
            "lines_scanned": sum(s.lines_scanned for s in latest.values()),
            "gate_failed": sum(1 for s in latest.values() if s.gate_failed),
            "ai_triaged": len(triaged),
            "ai_false_positives": len(ai_fp),
            "new_since_last": delta["new"],
            "fixed_since_last": delta["fixed"],
        },
        "severity": {s: severity.get(s, 0) for s in SEVERITIES},
        "trend": trend,
        "top_files": [
            {"file": name, "total": total, **{s: files_sev[name].get(s, 0) for s in SEVERITIES}}
            for name, total in files.most_common(5)
        ],
        "owasp": owasp.most_common(),
        "cwe": cwe.most_common(10),
        "engines": dict(engines),
        "latest_scans": [scan_to_dict(s) for s in sorted(latest.values(), key=lambda s: s.created_at, reverse=True)],
    }


def severity_rank(name: str) -> int:
    return int(Severity.parse(name))
