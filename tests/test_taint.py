"""Taint analysis: fontes, propagação, sanitizadores, guardas e fluxo interprocedural."""
import textwrap

from sast_engine.scanner import ScanConfig, scan_sources

FLASK = "from flask import Flask, request, redirect\nimport os, subprocess, requests, sqlite3\napp = Flask(__name__)\n"


def taint(code: str, files: dict | None = None):
    sources = files or {"app.py": FLASK + textwrap.dedent(code)}
    result = scan_sources(sources, ScanConfig())
    return [f for f in result.findings if f.rule_id.startswith("TAINT-")]


def test_direct_flow_to_sql():
    found = taint("""
        @app.route("/u")
        def u():
            nome = request.args.get("nome")
            q = "SELECT * FROM u WHERE n = '" + nome + "'"
            sqlite3.connect("x").execute(q)
    """)
    assert [f.rule_id for f in found] == ["TAINT-SQLI"]
    assert found[0].trace[0].description.startswith("fonte")
    assert found[0].trace[-1].description.startswith("sink")


def test_parameterized_query_is_safe():
    assert taint("""
        @app.route("/u")
        def u():
            nome = request.args.get("nome")
            sqlite3.connect("x").execute("SELECT * FROM u WHERE n = ?", (nome,))
    """) == []


def test_reassignment_kills_taint():
    assert taint("""
        @app.route("/u")
        def u():
            cmd = request.args["c"]
            cmd = "ls"
            os.system(cmd)
    """) == []


def test_sanitizers():
    assert taint("""
        import shlex
        @app.route("/u")
        def u():
            os.system("ping " + shlex.quote(request.args["h"]))
            n = int(request.args["n"])
            os.system(f"seq {n}")
    """) == []


def test_allowlist_guard_with_early_exit():
    assert taint("""
        PERMITIDOS = {"a.com"}
        @app.route("/u")
        def u():
            url = request.args["url"]
            if url not in PERMITIDOS:
                return "negado", 400
            return requests.get(url, timeout=3).text
    """) == []


def test_guard_only_protects_validated_branch():
    found = taint("""
        @app.route("/u")
        def u():
            url = request.args["url"]
            if url.startswith("https://ok"):
                requests.get(url, timeout=3)
            requests.get(url, timeout=3)
    """)
    assert [f.line for f in found] == [10]  # só a chamada fora do if validado


def test_route_parameters_are_sources():
    found = taint("""
        @app.route("/f/<nome>")
        def f(nome):
            return open("/srv/" + nome).read()
    """)
    assert [f.rule_id for f in found] == ["TAINT-PATH"]


def test_fastapi_query_params_and_depends():
    code = textwrap.dedent("""
        import os
        from fastapi import FastAPI, Depends
        app = FastAPI()
        def get_db(): ...
        @app.get("/x")
        def x(cmd: str, db=Depends(get_db)):
            os.system(cmd)
            os.system(db)
    """)
    found = taint("", {"main.py": code})
    assert [(f.rule_id, f.line) for f in found] == [("TAINT-CMDI", 8)]


def test_interprocedural_same_file():
    found = taint("""
        def montar(c):
            return "echo " + c
        def rodar(cmd):
            subprocess.call(cmd, shell=True)
        @app.route("/u")
        def u():
            rodar(montar(request.args["c"]))
    """)
    assert [(f.rule_id, f.line) for f in found] == [("TAINT-CMDI", 8)]
    assert any("passado para rodar()" in s.description for s in found[0].trace)


def test_interprocedural_across_files():
    files = {
        "pkg/db.py": "def buscar(cur, nome):\n    cur.execute('SELECT ' + nome)\n",
        "pkg/web.py": FLASK + "from pkg.db import buscar\n@app.route('/x')\ndef x():\n    buscar(None, request.args['n'])\n",
    }
    found = taint("", files)
    assert [(f.file, f.rule_id) for f in found] == [("pkg/db.py", "TAINT-SQLI")]
    assert found[0].trace[0].file == "pkg/web.py"


def test_method_call_via_self():
    found = taint("""
        class Servico:
            def executar(self, c):
                os.system(c)
            def handle(self):
                self.executar(input())
    """)
    assert [f.rule_id for f in found] == ["TAINT-CMDI"]


def test_flask_html_return_xss_and_escape():
    found = taint("""
        from markupsafe import escape
        @app.route("/a")
        def a():
            return f"<b>{request.args['n']}</b>"
        @app.route("/b")
        def b():
            return f"<b>{escape(request.args['n'])}</b>"
        @app.route("/c")
        def c():
            return {"n": request.args['n']}
    """)
    assert [(f.rule_id, f.line) for f in found] == [("TAINT-XSS", 8)]


def test_loop_and_container_propagation():
    found = taint("""
        @app.route("/a")
        def a():
            partes = []
            for p in request.args.getlist("p"):
                partes.append(p)
            cmd = " ".join(partes)
            os.system(cmd)
    """)
    assert [f.rule_id for f in found] == ["TAINT-CMDI"]


def test_taint_supersedes_heuristic_on_same_line():
    result = scan_sources({"a.py": FLASK + "@app.route('/')\ndef a():\n    eval(request.args['x'])\n"})
    assert [f.rule_id for f in result.findings] == ["TAINT-CODE"]
