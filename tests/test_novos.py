"""Funcionalidades adicionadas para cobrir 100% do enunciado/PDF."""
import json

import pytest

from sast_engine.ai import AITriage
from sast_engine.ai.triage import strip_comments
from sast_engine.models import Finding, Severity
from sast_engine.rules.catalog import CATALOG, REFERENCE_CVES, reference_cves
from sast_engine.scanner import ScanConfig, scan_sources

from test_ai import FakeClient


def rules_js(code):
    return [(f.rule_id, f.line) for f in scan_sources({"a.js": code}, ScanConfig()).findings]


# ------------------------------------------------------------ taint em JavaScript
@pytest.mark.parametrize("code,expected", [
    ("app.get('/', (req, res) => { exec(`ls ${req.query.d}`); });", "TAINT-CMDI"),
    ("app.get('/', (req, res) => { const { id } = req.params; db.query('SELECT ' + id); });", "TAINT-SQLI"),
    ("app.get('/', (req, res) => { res.send(`<b>${req.query.n}</b>`); });", "TAINT-XSS"),
    ("app.get('/', (req, res) => { fs.readFileSync(req.body.arquivo); });", "TAINT-PATH"),
    ("app.get('/', async (req, res) => { await fetch(req.query.url); });", "TAINT-SSRF"),
    ("app.get('/', (req, res) => { res.redirect(302, req.query.next); });", "TAINT-REDIRECT"),
    ("el.innerHTML = location.hash;", "TAINT-XSS"),
])
def test_js_taint_detects(code, expected):
    assert expected in {r for r, _ in rules_js(code)}


@pytest.mark.parametrize("code", [
    "app.get('/', (req, res) => { db.query('SELECT * FROM u WHERE id = $1', [req.query.id]); });",
    "app.get('/', (req, res) => { const n = parseInt(req.query.n, 10); exec(`seq ${n}`); });",
    "app.get('/', (req, res) => { res.json({ nome: req.query.nome }); });",
    "app.get('/', (req, res) => { res.sendFile(path.basename(req.params.f)); });",
    "app.get('/', (req, res) => { let c = req.query.c; c = 'ls'; exec(c); });",
    "setTimeout(() => atualizar(), 100);",
])
def test_js_taint_safe_cases(code):
    assert not [r for r, _ in rules_js(code) if r.startswith("TAINT-")]


def test_js_taint_supersedes_heuristic():
    found = rules_js("app.get('/', (req, res) => { eval(req.query.x); });")
    assert ("TAINT-CODE", 1) in found and ("JS001", 1) not in found


# ------------------------------------------------------- varredura semântica
def test_strip_comments_keeps_line_numbers():
    src = "x = 1  # expect: PY001\n# comentário\ny = '# não é comentário'\n"
    out = strip_comments(src)
    assert "expect" not in out and "# não é comentário" in out and len(out.splitlines()) == 3


def test_semantic_review_drops_duplicates_of_known_findings():
    known = [Finding(rule_id="TAINT-SQLI", title="SQLi", message="", file="a.py", line=10)]
    source = "\n".join(f"x{i} = {i}" for i in range(1, 31))
    client = FakeClient({"issues": [
        {"line": 11, "title": "SQLi de novo", "severity": "HIGH", "confidence": 0.9, "explanation": "x"},
        {"line": 25, "title": "IDOR", "cwe": "CWE-639", "severity": "HIGH", "confidence": 0.9, "explanation": "x"},
    ]})
    found = AITriage(client).semantic_review("a.py", source, "python", known)
    assert [(f.line, f.title) for f in found] == [(25, "IDOR")]


def test_semantic_prompt_has_no_comments_and_lists_known():
    class Spy(FakeClient):
        def chat_json(self, system, user, schema=None):
            self.user = user
            return {"issues": []}
    spy = Spy()
    known = [Finding(rule_id="PY002", title="eval", message="", file="a.py", line=1)]
    AITriage(spy).semantic_review("a.py", "eval(x)  # expect: PY002\n", "python", known)
    assert "expect" not in spy.user and "PY002" in spy.user


def test_logic_flaw_sample_has_no_rule_findings():
    from pathlib import Path
    src = (Path(__file__).parent.parent / "samples/vulnerable_app/pedidos.py").read_text()
    assert scan_sources({"pedidos.py": src}).findings == []


# ------------------------------------------------------------ CVEs de referência
def test_pdf_cves_are_in_catalog():
    ids = {r.cve for refs in REFERENCE_CVES.values() for r in refs}
    assert {"CVE-2014-3704", "CVE-2020-11022", "CVE-2020-13379", "CVE-2021-41773"} <= ids
    assert reference_cves("CWE-89")[0].cve == "CVE-2014-3704"


def test_every_taint_rule_has_a_real_cve_example():
    for meta in CATALOG.values():
        if meta.kind == "taint" and meta.cwe not in {"CWE-601"}:
            assert reference_cves(meta.cwe), meta.id


# ------------------------------------------------------------------ RAG / LangChain
def test_knowledge_documents_cover_catalog_and_cves():
    from sast_engine.ai.rag import knowledge_documents
    docs = knowledge_documents()
    kinds = {m["kind"] for _, m in docs}
    assert kinds == {"regra", "cve"} and len(docs) >= len(CATALOG)


def test_rag_context_is_injected_into_prompt(monkeypatch):
    import sast_engine.ai.rag as rag

    class Spy(FakeClient):
        use_rag = True
        def chat_json(self, system, user, schema=None):
            self.user = user
            return {"verdict": "true_positive", "confidence": 0.9, "severity": "HIGH",
                    "justification": "j", "remediation": "r", "fixed_code": ""}
    monkeypatch.setattr(rag, "rag_context", lambda f, url=None, k=3: ("Base de conhecimento recuperada (RAG):\n- CVE-2014-3704 Drupalgeddon", ["CVE-2014-3704"]))
    spy = Spy()
    f = Finding(rule_id="TAINT-SQLI", title="SQL Injection", message="m", file="a.py", line=1, severity=Severity.CRITICAL, cwe="CWE-89")
    analysis = AITriage(spy).analyze(f, "cur.execute(q)\n")
    assert "Drupalgeddon" in spy.user and analysis.rag_documents == ["CVE-2014-3704"]


def test_rag_disabled_gracefully(monkeypatch):
    from sast_engine.ai import rag
    monkeypatch.setenv("AI_RAG", "0")
    rag.get_knowledge_base.cache_clear()
    assert rag.rag_context(Finding(rule_id="PY001", title="t", message="m", file="a", line=1)) == ("", [])
    rag.get_knowledge_base.cache_clear()


def test_langchain_client_falls_back_to_llm_unavailable_when_offline():
    from sast_engine.ai import LangChainOllamaClient, LLMUnavailable
    client = LangChainOllamaClient(base_url="http://127.0.0.1:9", timeout=2)
    with pytest.raises(LLMUnavailable):
        client.chat_json("s", "u", {"type": "object"})


# ---------------------------------------------------------------- GitLab
def test_gitlab_sast_report_format():
    from sast_engine.reporters import to_gitlab_sast
    result = scan_sources({"a.py": "def f(x):\n    eval(x)\n"})
    report = json.loads(to_gitlab_sast(result))
    vuln = report["vulnerabilities"][0]
    assert report["version"].startswith("15.") and report["scan"]["type"] == "sast"
    assert vuln["severity"] == "Medium" and vuln["location"] == {"file": "a.py", "start_line": 2, "end_line": 2}
    assert {"type": "cwe", "name": "CWE-95", "value": "95", "url": "https://cwe.mitre.org/data/definitions/95.html"} in vuln["identifiers"]


def test_semantic_by_function_maps_answers_to_cwes():
    """Rotas são achadas pela AST; as respostas objetivas do LLM viram achados com CWE."""
    class Oracle(FakeClient):
        def chat_json(self, system, user, schema=None):
            idor = "ver(" in user
            return {"requires_authentication": True, "accesses_resource_by_id": idor,
                    "checks_resource_owner": False, "modifies_data": "salvar" in user,
                    "trusts_client_sensitive_value": "percentual" in user, "sensitive_value": "percentual",
                    "explanation": "x"}
    src = (
        "from flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/p/<int:i>')\ndef ver(i):\n    return Pedido.buscar(i)  # comentário\n"
        "@app.route('/d', methods=['POST'])\ndef desconto():\n    c.total *= 1 - float(request.json['percentual'])\n    c.salvar()\n"
        "def helper():\n    pass\n"
    )
    found = AITriage(Oracle()).semantic_review("a.py", src)
    assert {(f.line, f.cwe) for f in found} == {(4, "CWE-639"), (7, "CWE-602")}
    assert all(f.rule_id == "AI-SEMANTIC" and f.engine == "ai/llama3-fake" for f in found)


def test_semantic_by_function_ignores_cwe_already_known():
    class Oracle(FakeClient):
        def chat_json(self, system, user, schema=None):
            return {"requires_authentication": False, "accesses_resource_by_id": False, "checks_resource_owner": True,
                    "modifies_data": True, "trusts_client_sensitive_value": False, "explanation": ""}
    src = "from flask import Flask\napp = Flask(__name__)\n@app.post('/x')\ndef x():\n    salvar()\n"
    known = [Finding(rule_id="X", title="t", message="", file="a.py", line=5, cwe="CWE-306")]
    assert AITriage(Oracle()).semantic_review("a.py", src, "python", known) == []
