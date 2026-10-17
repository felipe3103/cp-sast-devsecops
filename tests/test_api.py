"""API de ponta a ponta (SQLite + Celery em modo síncrono)."""
import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def zip_dir(path: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in path.rglob("*.py"):
            zf.write(f, f"projeto/{f.relative_to(path)}")
    return buf.getvalue()


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_dashboard_served(client):
    assert "SentinelaSAST" in client.get("/").text


def test_upload_zip_scan_and_metrics(client):
    data = zip_dir(ROOT / "samples" / "vulnerable_app")
    r = client.post("/api/v1/scans/upload", files={"file": ("app.zip", data, "application/zip")}, data={"project": "demo"})
    assert r.status_code == 202
    scan = client.get(f"/api/v1/scans/{r.json()['id']}").json()
    assert scan["status"] == "completed" and scan["gate_failed"] is True
    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert any(f["rule_id"] == "TAINT-SQLI" for f in findings)

    detail = client.get(f"/api/v1/findings/{findings[0]['id']}").json()
    assert detail["context"]["lines"]

    m = client.get("/api/v1/metrics", params={"project": "demo"}).json()
    assert m["kpis"]["critical"] > 0 and len(m["top_files"]) <= 5 and m["trend"]
    assert client.get(f"/api/v1/scans/{scan['id']}/report.sarif").json()["version"] == "2.1.0"


def test_ai_triage_falls_back_to_knowledge_base(client):
    r = client.post("/api/v1/scans/snippet", json={"code": "import os\ndef f(c):\n    os.system(c)\n", "project": "ai"})
    fid = client.get(f"/api/v1/scans/{r.json()['id']}/findings").json()[0]["id"]
    ai = client.post(f"/api/v1/findings/{fid}/ai").json()
    assert ai["source"] == "knowledge_base" and ai["remediation"]


def test_mark_false_positive(client):
    r = client.post("/api/v1/scans/snippet", json={"code": "eval(x)\n", "project": "fp"})
    fid = client.get(f"/api/v1/scans/{r.json()['id']}/findings").json()[0]["id"]
    assert client.patch(f"/api/v1/findings/{fid}", json={"status": "false_positive"}).json()["status"] == "false_positive"
    assert client.get("/api/v1/metrics", params={"project": "fp"}).json()["kpis"]["open_findings"] == 0


def test_zip_slip_rejected(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/evil.py", "x = 1")
    r = client.post("/api/v1/scans/upload", files={"file": ("a.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 400 and "inseguro" in r.json()["detail"]


def test_git_host_not_allowed(client):
    r = client.post("/api/v1/scans/git", json={"repo_url": "https://evil.example.com/a/b"})
    assert r.status_code == 400
    r = client.post("/api/v1/scans/git", json={"repo_url": "file:///etc/passwd"})
    assert r.status_code == 400


def test_ci_ingestion_requires_token(client):
    payload = {"project": "ci", "ref": "main@abc", "summary": {"files_scanned": 1}, "findings": []}
    assert client.post("/api/v1/scans/ci", json=payload).status_code == 401
    r = client.post("/api/v1/scans/ci", json=payload, headers={"X-API-Token": "token-de-teste"})
    assert r.status_code == 201 and r.json()["gate_failed"] is False


def test_rules_endpoint(client):
    ids = {r["id"] for r in client.get("/api/v1/rules").json()}
    assert {"PY001", "PY002", "PY003", "TAINT-SQLI"} <= ids


def test_metrics_include_reference_cves_and_semantic_status(client):
    r = client.post("/api/v1/scans/snippet", json={
        "code": "from flask import request\nimport sqlite3\ndef f():\n    sqlite3.connect('x').execute('SELECT ' + request.args['q'])\n",
        "project": "cve"})
    scan = client.get(f"/api/v1/scans/{r.json()['id']}").json()
    assert scan["semantic_status"] == "none"
    m = client.get("/api/v1/metrics", params={"project": "cve"}).json()
    assert any(c["cve"] == "CVE-2014-3704" and c["findings"] >= 1 for c in m["reference_cves"])
    fid = client.get(f"/api/v1/scans/{scan['id']}/findings").json()[0]["id"]
    assert client.get(f"/api/v1/findings/{fid}").json()["reference_cves"][0]["cve"] == "CVE-2014-3704"


def test_semantic_endpoint_marks_done_without_llm(client):
    r = client.post("/api/v1/scans/snippet", json={"code": "x = 1\n", "project": "sem"})
    sid = r.json()["id"]
    assert client.post(f"/api/v1/scans/{sid}/semantic").status_code == 202
    scan = client.get(f"/api/v1/scans/{sid}").json()
    assert scan["semantic_status"] == "done" and scan["semantic_found"] == 0
