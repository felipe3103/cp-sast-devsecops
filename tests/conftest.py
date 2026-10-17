import os
import sys
import tempfile
from pathlib import Path

# Configura a API para testes ANTES de importá-la: SQLite temporário e Celery síncrono.
_tmp = tempfile.mkdtemp(prefix="sentinela-test-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp}/test.db")
os.environ.setdefault("CELERY_EAGER", "1")
os.environ.setdefault("SAST_API_TOKEN", "token-de-teste")
os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:9")  # porta fechada: força fallback

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "services" / "api")]

import pytest  # noqa: E402

from sast_engine.scanner import ScanConfig, scan_sources  # noqa: E402


@pytest.fixture
def scan():
    """scan(code) -> lista de (rule_id, linha). Facilita asserts compactos."""
    def _scan(code: str, filename: str = "alvo.py", **cfg):
        result = scan_sources({filename: code}, ScanConfig(**cfg))
        return [(f.rule_id, f.line) for f in result.findings]
    return _scan
