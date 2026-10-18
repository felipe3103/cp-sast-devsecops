"""Módulo de IA com cliente Ollama simulado: guardrails, validação da correção e fallback."""
from sast_engine.ai import AITriage, LLMUnavailable
from sast_engine.models import Confidence, Finding, Severity
from sast_engine.scanner import scan_sources

VULN = 'import os\ndef f(c):\n    os.system("ls " + c)\n'


class FakeClient:
    model = "llama3-fake"
    base_url = "http://fake"

    def __init__(self, response=None, error=False):
        self.response, self.error, self.calls = response, error, 0

    def chat_json(self, system, user, schema=None):
        self.calls += 1
        if self.error:
            raise LLMUnavailable("offline")
        return self.response

    def is_available(self):
        return not self.error


def finding(rule="PY003", severity=Severity.HIGH, confidence=Confidence.MEDIUM):
    return Finding(rule_id=rule, title="t", message="m", file="a.py", line=3, severity=severity,
                   confidence=confidence, cwe="CWE-78", snippet='    os.system("ls " + c)')


def response(**kw):
    base = {"verdict": "true_positive", "confidence": 0.9, "severity": "HIGH", "justification": "j",
            "exploit_scenario": "e", "remediation": "r",
            "fixed_code": 'import subprocess\ndef f(c):\n    subprocess.run(["ls", c], check=True)'}
    return {**base, **kw}


def test_valid_fix_is_verified():
    analysis = AITriage(FakeClient(response())).analyze(finding(), VULN)
    assert analysis.source == "llm" and analysis.fix_validated is True


def test_fix_that_still_vulnerable_is_rejected():
    bad = response(fixed_code='import os\ndef f(c):\n    os.system("ls " + c.strip())')
    analysis = AITriage(FakeClient(bad)).analyze(finding(), VULN)
    assert analysis.fix_validated is False and "PY003" in analysis.fix_validation_note


def test_fix_that_does_not_compile_is_rejected():
    analysis = AITriage(FakeClient(response(fixed_code="def f(:"))).analyze(finding(), VULN)
    assert analysis.fix_validated is False and "não compila" in analysis.fix_validation_note


def test_severity_change_is_bounded_to_one_level():
    analysis = AITriage(FakeClient(response(severity="INFO"))).analyze(finding(severity=Severity.HIGH), VULN)
    assert analysis.severity == "MEDIUM" and analysis.notes


def test_confident_false_positive_is_suppressed():
    analysis = AITriage(FakeClient(response(verdict="false_positive", confidence=0.95))).analyze(finding(), VULN)
    assert analysis.suppressed is True


def test_low_confidence_false_positive_goes_to_review():
    analysis = AITriage(FakeClient(response(verdict="false_positive", confidence=0.5))).analyze(finding(), VULN)
    assert analysis.suppressed is False and analysis.verdict == "needs_review"


def test_ai_cannot_suppress_proven_taint_flow():
    f = finding(rule="TAINT-CMDI", severity=Severity.CRITICAL, confidence=Confidence.HIGH)
    analysis = AITriage(FakeClient(response(verdict="false_positive", confidence=0.99))).analyze(f, VULN)
    assert analysis.suppressed is False and analysis.verdict == "needs_review"


def test_fallback_to_knowledge_base_when_offline():
    analysis = AITriage(FakeClient(error=True)).analyze(finding(), VULN)
    assert analysis.source == "knowledge_base" and "subprocess" in analysis.fixed_code


def test_cache_avoids_repeated_llm_calls():
    client = FakeClient(response())
    triage = AITriage(client)
    triage.analyze(finding(), VULN)
    triage.analyze(finding(), VULN)
    assert client.calls == 1


def test_semantic_review_discards_hallucinated_lines():
    client = FakeClient({"issues": [
        {"line": 2, "title": "IDOR", "cwe": "CWE-639", "severity": "CRITICAL", "confidence": 0.9, "explanation": "x"},
        {"line": 999, "title": "inventado", "severity": "HIGH", "confidence": 0.9, "explanation": "x"},
        {"line": 1, "title": "fraco", "severity": "HIGH", "confidence": 0.3, "explanation": "x"},
    ]})
    found = AITriage(client).semantic_review("a.py", VULN)
    assert [(f.line, f.severity) for f in found] == [(2, Severity.HIGH)]  # CRITICAL limitado a HIGH


def test_ai_suppressed_findings_do_not_block_gate():
    from sast_engine.gate import GatePolicy, evaluate
    findings = scan_sources({"a.py": VULN}).findings
    findings[0].extra["ai_suppressed"] = True
    assert evaluate(findings, GatePolicy())["failed"] is False


class SequenceClient(FakeClient):
    """Devolve respostas diferentes a cada chamada (triagem, depois nova tentativa)."""

    def __init__(self, responses):
        super().__init__()
        self.responses = list(responses)

    def chat_json(self, system, user, schema=None):
        self.calls += 1
        self.last_user = user
        return self.responses.pop(0)


def test_fix_self_correction_loop():
    good = 'import subprocess\ndef f(c):\n    subprocess.run(["ls", c], check=True)'
    client = SequenceClient([response(fixed_code="def f(c):\n    x ="), {"fixed_code": good}])
    analysis = AITriage(client).analyze(finding(), VULN)
    assert client.calls == 2 and "não compila" in client.last_user  # erro do validador volta ao LLM
    assert analysis.fix_validated is True and analysis.fixed_code == good
    assert "autocorreção" in analysis.fix_validation_note


def test_fix_validated_against_whole_project_interprocedural():
    """A correção que mantém a concatenação no SQL só é pega re-escaneando o projeto inteiro."""
    from sast_engine.scanner import scan_sources
    files = {
        "db.py": "def buscar(cur, nome):\n    sql = 'SELECT * FROM u WHERE n = ' + nome\n    cur.execute(sql)\n",
        "web.py": "from flask import Flask, request\nfrom db import buscar\napp = Flask(__name__)\n"
                  "@app.route('/x')\ndef x():\n    return buscar(None, request.args['n'])\n",
    }
    sqli = next(f for f in scan_sources(files).findings if f.rule_id == "TAINT-SQLI")
    ruim = "def buscar(cur, nome):\n    sql = 'SELECT * FROM u WHERE n = ' + nome\n    cur.execute(sql, ())"
    boa = "def buscar(cur, nome):\n    cur.execute('SELECT * FROM u WHERE n = %s', (nome,))"
    triage = AITriage(SequenceClient([response(fixed_code=ruim), {"fixed_code": boa}]))
    analysis = triage.analyze(sqli, files["db.py"], files)
    assert analysis.fix_validated is True and analysis.fixed_code == boa
    assert "TAINT-SQLI" in analysis.notes[0] or "TAINT-SQLI" in triage.client.last_user


def test_fix_that_introduces_new_vulnerability_is_rejected():
    from sast_engine.ai.triage import validate_fix
    piora = 'import subprocess\ndef f(c):\n    subprocess.run(["ls", c], check=True)\n    eval(c)'
    ok, note = validate_fix(finding(), piora, VULN, {})
    assert ok is False and "introduz PY002" in note


def test_fix_that_deletes_functionality_is_rejected():
    """Visto com o LLM real: `query = f` "eliminava" o SQLi apagando a consulta."""
    from sast_engine.ai.triage import validate_fix
    src = "from flask import request\nimport sqlite3\ndef u():\n    query = 'SELECT ' + request.args['n']\n    rows = sqlite3.connect('x').execute(query).fetchall()\n    return rows\n"
    sqli = next(f for f in scan_sources({"a.py": src}).findings if f.rule_id == "TAINT-SQLI")
    ok, note = validate_fix(sqli, "query = f", src, {"a.py": src})
    assert ok is False and "remove a operação original" in note
    ok, note = validate_fix(sqli, "rows = sqlite3.connect('x').execute('SELECT ?', (request.args['n'],)).fetchall()", src, {"a.py": src})
    assert ok is True, note


def test_fix_must_keep_return_value():
    from sast_engine.ai.triage import preserves_behavior
    src = "def f(c):\n    return eval(c)\n"
    assert preserves_behavior(src, 2, "def f(c):\n    pass")[0] is False
    assert preserves_behavior(src, 2, "def f(c):\n    return ast.literal_eval(c)")[0] is True
