"""API REST da plataforma SentinelaSAST (FastAPI).

Documentação interativa em /docs. Dashboard executivo em /.
"""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from sast_engine import __version__, reporters
from sast_engine.ai import OllamaClient
from sast_engine.gate import GatePolicy, evaluate
from sast_engine.models import Finding, ScanResult, Severity
from sast_engine.rules.catalog import CATALOG

from . import services
from .config import settings
from .db import FindingRow, Project, Scan, get_session, init_db
from .worker import run_scan, semantic_review_task, triage_finding_task

STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="SentinelaSAST API",
    version=__version__,
    description="Plataforma SAST com taint analysis, triagem por LLM local e Security Gates.",
)
if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ============================================================= schemas
class GitScanRequest(BaseModel):
    repo_url: str = Field(examples=["https://github.com/pallets/flask"])
    project: str | None = None
    ref: str | None = None


class SnippetScanRequest(BaseModel):
    code: str = Field(max_length=500_000)
    filename: str = "snippet.py"
    project: str = "playground"


class CIReport(BaseModel):
    project: str
    ref: str = ""
    summary: dict = {}
    findings: list[dict] = []
    gate: dict | None = None


class FindingUpdate(BaseModel):
    status: Literal["open", "false_positive", "accepted_risk", "fixed"]


def require_token(x_api_token: str = Header(default="")) -> None:
    if settings.api_token and not hmac.compare_digest(x_api_token, settings.api_token):
        raise HTTPException(401, "token inválido")


def _enqueue_scan(session: Session, project: str, source: str, ref: str, **task_kwargs) -> Scan:
    scan = Scan(project=services.get_or_create_project(session, project), source=source, ref=ref[:300])
    session.add(scan)
    session.commit()
    run_scan.delay(scan.id, **task_kwargs)
    session.refresh(scan)
    return scan


# ================================================================ rotas
@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/v1/rules")
def list_rules() -> list[dict]:
    return [
        {"id": r.id, "title": r.title, "cwe": r.cwe, "owasp": r.owasp, "severity": r.severity.name,
         "kind": r.kind, "description": r.description, "remediation": r.remediation}
        for r in CATALOG.values()
    ]


@app.get("/api/v1/ai/status")
def ai_status() -> dict:
    client = OllamaClient()
    return {"url": client.base_url, "model": client.model, "available": client.is_available()}


@app.get("/api/v1/projects")
def list_projects(session: Session = Depends(get_session)) -> list[dict]:
    return [{"id": p.id, "name": p.name, "scans": len(p.scans)} for p in session.scalars(select(Project).order_by(Project.name))]


# --------------------------------------------------------- varreduras
@app.post("/api/v1/scans/upload", status_code=202)
async def scan_upload(file: UploadFile = File(...), project: str = Form("default"), session: Session = Depends(get_session)) -> dict:
    data = await file.read(settings.max_upload_mb * 1024 * 1024 + 1)
    name = file.filename or "upload"
    try:
        if name.endswith(".zip"):
            files = services.extract_zip(data)
        elif Path(name).suffix in {".py", ".js"}:
            files = {Path(name).name: data.decode("utf-8", errors="replace")}
        else:
            raise services.IngestError("envie um .zip, .py ou .js")
    except services.IngestError as exc:
        raise HTTPException(400, str(exc)) from exc
    scan = _enqueue_scan(session, project, "upload", name, files=files)
    return services.scan_to_dict(scan)


@app.post("/api/v1/scans/git", status_code=202)
def scan_git(body: GitScanRequest, session: Session = Depends(get_session)) -> dict:
    host = urlparse(body.repo_url).hostname
    if not services.GIT_URL_RE.match(body.repo_url) or host not in settings.allowed_git_hosts:
        raise HTTPException(400, f"URL inválida. Use https://<host>/<dono>/<repo> com host em {', '.join(settings.allowed_git_hosts)}")
    project = body.project or body.repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    scan = _enqueue_scan(session, project, "git", f"{body.repo_url}@{body.ref or 'HEAD'}", repo_url=body.repo_url, ref=body.ref)
    return services.scan_to_dict(scan)


@app.post("/api/v1/scans/snippet", status_code=202)
def scan_snippet(body: SnippetScanRequest, session: Session = Depends(get_session)) -> dict:
    filename = Path(body.filename).name or "snippet.py"
    if Path(filename).suffix not in {".py", ".js"}:
        raise HTTPException(400, "extensão deve ser .py ou .js")
    scan = _enqueue_scan(session, body.project, "snippet", filename, files={filename: body.code})
    return services.scan_to_dict(scan)


@app.post("/api/v1/scans/ci", status_code=201, dependencies=[Depends(require_token)])
def scan_from_ci(report: CIReport, session: Session = Depends(get_session)) -> dict:
    """Recebe o relatório JSON gerado pela CLI no pipeline (GitHub Actions)."""
    result = ScanResult(
        findings=[Finding.from_dict(f) for f in report.findings],
        files_scanned=report.summary.get("files_scanned", 0),
        lines_scanned=report.summary.get("lines_scanned", 0),
        duration_ms=report.summary.get("duration_ms", 0),
    )
    scan = Scan(project=services.get_or_create_project(session, report.project), source="ci", ref=report.ref[:300], status="running")
    session.add(scan)
    session.flush()
    gate = report.gate or evaluate(result.findings, GatePolicy())
    services.persist_result(session, scan, result, None, gate)
    session.commit()
    return services.scan_to_dict(scan)


@app.get("/api/v1/scans")
def list_scans(project: str | None = None, limit: int = Query(50, le=500), session: Session = Depends(get_session)) -> list[dict]:
    query = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    if project:
        query = query.join(Project).where(Project.name == project)
    return [services.scan_to_dict(s) for s in session.scalars(query)]


def _get_scan(session: Session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan não encontrado")
    return scan


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session)) -> dict:
    return services.scan_to_dict(_get_scan(session, scan_id))


@app.get("/api/v1/scans/{scan_id}/findings")
def scan_findings(
    scan_id: int,
    severity: str | None = None,
    status: str | None = None,
    file: str | None = None,
    session: Session = Depends(get_session),
) -> list[dict]:
    rows = _get_scan(session, scan_id).findings
    if severity:
        allowed = {s.strip().upper() for s in severity.split(",")}
        rows = [r for r in rows if r.severity in allowed]
    if status:
        rows = [r for r in rows if r.status == status]
    if file:
        rows = [r for r in rows if r.file == file]
    rows = sorted(rows, key=lambda r: (-Severity.parse(r.severity), -r.risk_score, r.file, r.line))
    return [services.finding_to_dict(r, with_ai=False) for r in rows]


@app.get("/api/v1/scans/{scan_id}/report.{fmt}")
def scan_report(scan_id: int, fmt: Literal["sarif", "md", "json"], session: Session = Depends(get_session)) -> Response:
    scan = _get_scan(session, scan_id)
    result = services.scan_result_from_db(scan)
    gate = {"failed": bool(scan.gate_failed), "reason": scan.gate_reason} if scan.gate_failed is not None else None
    if fmt == "sarif":
        return Response(reporters.to_sarif(result), media_type="application/sarif+json",
                        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.sarif"})
    if fmt == "md":
        return PlainTextResponse(reporters.to_markdown(result, gate), media_type="text/markdown")
    return Response(reporters.to_json(result, gate), media_type="application/json")


@app.post("/api/v1/scans/{scan_id}/ai", status_code=202)
def scan_ai(scan_id: int, limit: int = Query(15, le=100), session: Session = Depends(get_session)) -> dict:
    scan = _get_scan(session, scan_id)
    rows = sorted((r for r in scan.findings if r.ai_status in {"none", "failed"}), key=lambda r: -r.risk_score)[:limit]
    for row in rows:
        row.ai_status = "pending"
    session.commit()
    for row in rows:
        triage_finding_task.delay(row.id)
    return {"queued": len(rows)}


@app.post("/api/v1/scans/{scan_id}/semantic", status_code=202)
def scan_semantic(scan_id: int, session: Session = Depends(get_session)) -> dict:
    _get_scan(session, scan_id)
    semantic_review_task.delay(scan_id)
    return {"queued": True}


# ------------------------------------------------------------ achados
def _get_finding(session: Session, finding_id: int) -> FindingRow:
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(404, "achado não encontrado")
    return row


@app.get("/api/v1/findings/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session)) -> dict:
    row = _get_finding(session, finding_id)
    data = services.finding_to_dict(row)
    file_row = next((f for f in row.scan.files if f.path == row.file), None)
    if file_row:
        lines = file_row.content.splitlines()
        start = max(1, row.line - 8)
        data["context"] = {"start": start, "lines": lines[start - 1 : row.line + 8]}
    return data


@app.patch("/api/v1/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdate, session: Session = Depends(get_session)) -> dict:
    row = _get_finding(session, finding_id)
    row.status = body.status
    session.commit()
    return services.finding_to_dict(row)


@app.post("/api/v1/findings/{finding_id}/ai")
def finding_ai(finding_id: int, sync: bool = True, session: Session = Depends(get_session)) -> dict:
    row = _get_finding(session, finding_id)
    if sync:
        return services.triage_finding(session, row)
    row.ai_status = "pending"
    session.commit()
    triage_finding_task.delay(finding_id)
    return {"queued": True}


# ------------------------------------------------------------ métricas
@app.get("/api/v1/metrics")
def metrics(project: str | None = None, session: Session = Depends(get_session)) -> dict:
    return services.compute_metrics(session, project)
