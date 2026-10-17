"""Workers assíncronos (Celery + Redis).

Duas filas separadas permitem escalar cada tipo de trabalho de forma independente:
- `scans`: varreduras SAST (CPU-bound, rápidas)
- `ai`:    triagem com LLM (lenta, limitada pela GPU/CPU do Ollama)
"""
from __future__ import annotations

from celery import Celery
from sqlalchemy import select

from .config import settings
from .db import FindingRow, Scan, SessionLocal, init_db
from . import services

celery_app = Celery("sentinela", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_always_eager=settings.celery_eager,
    task_eager_propagates=False,
    task_routes={"sentinela.scan": {"queue": "scans"}, "sentinela.ai.*": {"queue": "ai"}},
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=900,
    broker_connection_retry_on_startup=True,
)


@celery_app.task(name="sentinela.scan", bind=True, max_retries=2)
def run_scan(self, scan_id: int, files: dict[str, str] | None = None, repo_url: str | None = None, ref: str | None = None):
    init_db()
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        try:
            if repo_url:
                files = services.clone_repository(repo_url, ref)
            services.execute_scan(session, scan, files or {})
        except Exception as exc:  # registra a falha no próprio scan
            session.rollback()
            scan = session.get(Scan, scan_id)
            scan.status = "failed"
            scan.error = str(exc)[:1000]
            session.commit()
            return
        if settings.ai_auto_triage:
            ids = session.scalars(
                select(FindingRow.id).where(FindingRow.scan_id == scan_id)
                .order_by(FindingRow.risk_score.desc()).limit(settings.ai_auto_limit)
            ).all()
            for finding_id in ids:
                triage_finding_task.delay(finding_id)


@celery_app.task(name="sentinela.ai.triage")
def triage_finding_task(finding_id: int):
    with SessionLocal() as session:
        row = session.get(FindingRow, finding_id)
        if row is None:
            return None
        try:
            return services.triage_finding(session, row)
        except Exception as exc:
            row.ai_status = "failed"
            row.ai = {"error": str(exc)[:500]}
            session.commit()
            return None


@celery_app.task(name="sentinela.ai.semantic")
def semantic_review_task(scan_id: int):
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return 0
        try:
            return services.semantic_review_scan(session, scan)
        except Exception as exc:
            session.rollback()
            scan = session.get(Scan, scan_id)
            scan.semantic_status = "failed"
            scan.error = f"varredura semântica: {exc}"[:1000]
            session.commit()
            return 0
