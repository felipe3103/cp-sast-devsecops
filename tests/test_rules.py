"""Regras determinísticas/heurísticas: cada regra tem caso positivo e negativo (falso positivo)."""
import textwrap

import pytest


def rules(findings):
    return {r for r, _ in findings}


# ------------------------------------------------- CP1: as 3 violações iniciais
@pytest.mark.parametrize("code", [
    'password = "Sup3rS3cr3t!"',
    'DB_PASS: str = "Pr0d#2024xyz"',
    'conn = connect(host="db", password="h4rdc0d3d!")',
    'cfg = {"api_key": "a8f5f167f44f4964e6c998dee827110c"}',
    'aws = "AKIAIOSFODNN7EXAMPLE"',
    'if senha == "admin@123":\n    pass',
    'import os\nkey = os.environ.get("APP_SECRET_KEY", "default_value")',
])
def test_hardcoded_secret_detected(scan, code):
    assert "PY001" in rules(scan(code))


@pytest.mark.parametrize("code", [
    'password = ""',
    'password = "changeme"',
    'password = "<sua-senha>"',
    'password = os.environ["DB_PASSWORD"]',
    'PASSWORD_FIELD = "password"',
    'TOKEN_URL = "https://auth.exemplo.com/token"',
    'token_type = "bearer"',
    'msg = "A senha deve ter pelo menos 12 caracteres"',
    'password = "${DB_PASSWORD}"',
    'password = os.getenv("DB_PASSWORD", "")',
])
def test_hardcoded_secret_false_positives(scan, code):
    assert "PY001" not in rules(scan("import os\n" + code))


def test_eval_dynamic_and_constant(scan):
    found = scan("def f(x):\n    eval(x)\n    eval('1+1')\n")
    assert ("PY002", 2) in found and ("PY002", 3) in found


def test_eval_constant_is_low_severity():
    from sast_engine.scanner import scan_sources
    f = scan_sources({"a.py": "eval('1+1')"}).findings[0]
    assert f.severity.name == "LOW"


def test_eval_alias_resolved(scan):
    assert "PY002" in rules(scan("import builtins\ndef f(x):\n    builtins.eval(x)"))


def test_shell_injection_with_alias(scan):
    code = "import subprocess as sp\ndef f(c):\n    sp.Popen(c, shell=True)\n"
    assert ("PY003", 3) in scan(code)


def test_os_system_constant_not_flagged(scan):
    assert scan("import os\nos.system('ls -la')") == []


def test_subprocess_list_without_shell_not_flagged(scan):
    assert scan("import subprocess\ndef f(h):\n    subprocess.run(['ping', '-c', '1', h])") == []


# ------------------------------------------------------------- regras extras
def test_pickle_and_yaml(scan):
    code = textwrap.dedent("""
        import pickle, yaml
        from pickle import loads
        def f(d):
            pickle.loads(d)
            loads(d)
            yaml.load(d)
            yaml.load(d, Loader=yaml.SafeLoader)
            yaml.safe_load(d)
    """)
    found = scan(code)
    assert [l for r, l in found if r == "PY004"] == [5, 6, 7]


def test_sql_string_building(scan):
    code = textwrap.dedent("""
        def f(cur, nome, ano):
            cur.execute(f"SELECT * FROM t WHERE nome = '{nome}'")
            cur.execute("SELECT * FROM t WHERE nome = %s", (nome,))
            cur.execute("SELECT * FROM t WHERE ano = %d" % int(ano))
            cur.execute("DELETE FROM t WHERE id = " + str(nome))
    """)
    found = scan(code)
    assert [l for r, l in found if r == "PY005"] == [3, 6]


def test_weak_hash(scan):
    code = "import hashlib\nhashlib.md5(b'x')\nhashlib.new('sha1')\nhashlib.md5(b'x', usedforsecurity=False)\nhashlib.sha256(b'x')"
    assert [l for r, l in scan(code) if r == "PY006"] == [2, 3]


def test_weak_random_only_in_security_context(scan):
    code = "import random\ntoken = random.randint(0, 10**6)\nindice = random.randint(0, 10)"
    assert [l for r, l in scan(code) if r == "PY007"] == [2]


def test_tls_verify_and_timeout(scan):
    found = scan("import requests\nrequests.get('https://x', verify=False)\nrequests.get('https://x', timeout=3)")
    assert ("PY008", 2) in found and ("PY017", 2) in found and all(l != 3 for _, l in found)


def test_debug_and_bind(scan):
    assert rules(scan("app.run(host='0.0.0.0', debug=True)")) == {"PY009", "PY018"}


def test_assert_only_for_authorization(scan):
    found = scan("def f(user, x):\n    assert user.is_admin\n    assert x > 0\n")
    assert found == [("PY010", 2)]


def test_misc_crypto_and_files(scan):
    code = textwrap.dedent("""
        import os, tempfile, jwt
        from Crypto.Cipher import AES
        from jinja2 import Environment
        tempfile.mktemp()
        AES.new(k, AES.MODE_ECB)
        jwt.decode(t, options={"verify_signature": False})
        os.chmod("f", 0o777)
        os.chmod("f", 0o600)
        Environment()
        Environment(autoescape=True)
    """)
    found = rules(scan(code))
    assert {"PY011", "PY012", "PY013", "PY014", "PY015"} <= found
    assert len([1 for r, l in scan(code) if r == "PY014"]) == 1


def test_suppression_comment(scan):
    code = "def f(x):\n    eval(x)  # nosast\n    eval(x)  # nosast: PY999\n    eval(x)  # nosast: PY002\n"
    assert scan(code) == [("PY002", 3)]


def test_syntax_error_reported_not_crash():
    from sast_engine.scanner import scan_sources
    result = scan_sources({"quebrado.py": "def f(:\n"})
    assert result.errors and result.findings == []


def test_javascript_rules(scan):
    code = "const password = 'xY9#kL2!pQ';\nel.innerHTML = data;\neval(x);\nel.textContent = data;"
    found = scan(code, filename="a.js")
    assert rules(found) == {"JS001", "JS002", "JS003"}
