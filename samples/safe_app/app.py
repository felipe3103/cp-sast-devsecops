"""Versão CORRIGIDA da aplicação de exemplo.

Implementa as mesmas funcionalidades de samples/vulnerable_app de forma segura.
O benchmark espera ZERO achados aqui: qualquer achado é um falso positivo.
"""
import ast
import hashlib
import html
import json
import os
import secrets
import shlex
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, redirect, render_template, request, url_for
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

UPLOAD_DIR = Path("/srv/uploads")
HOSTS_PERMITIDOS = {"api.exemplo.com.br", "status.exemplo.com.br"}
PASSWORD_FIELD = "password"
TOKEN_URL = "https://auth.exemplo.com.br/token"
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
API_KEY = "changeme"


def conexao():
    return sqlite3.connect(os.environ.get("DB_PATH", "dados.db"))


@app.route("/usuario")
def usuario():
    nome = request.args.get("nome", "")
    rows = conexao().execute("SELECT * FROM usuarios WHERE nome = ?", (nome,)).fetchall()
    return {"usuarios": rows}


@app.route("/relatorio/<int:ano>")
def relatorio(ano):
    cur = conexao().cursor()
    cur.execute("SELECT * FROM vendas WHERE ano = %d" % int(ano))
    return {"linhas": cur.fetchall()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if host not in HOSTS_PERMITIDOS:
        abort(400)
    saida = subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False)
    return saida.stdout


@app.route("/backup")
def backup():
    destino = shlex.quote(request.form["destino"])
    subprocess.run(f"tar czf /tmp/backup.tgz {destino}", shell=True, check=True)  # nosast: PY003
    return "ok"


@app.route("/calc")
def calc():
    valor = ast.literal_eval(request.args.get("expr", "0"))
    return str(valor)


@app.route("/arquivo")
def arquivo():
    nome = secure_filename(request.args.get("nome", ""))
    caminho = (UPLOAD_DIR / nome).resolve()
    with open(caminho) as fp:
        return fp.read()


@app.route("/arquivo/v2")
def arquivo_v2():
    caminho = os.path.realpath(os.path.join(UPLOAD_DIR, request.args.get("nome", "")))
    if not caminho.startswith(str(UPLOAD_DIR) + os.sep):
        abort(403)
    with open(caminho) as fp:
        return fp.read()


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in HOSTS_PERMITIDOS:
        abort(400)
    return requests.get(f"https://{urlparse(url).hostname}/status", timeout=5).text


@app.route("/ola")
def ola():
    nome = request.args.get("nome", "visitante")
    return f"<h1>Olá, {escape(nome)}!</h1>"


@app.route("/ola/v2")
def ola_v2():
    return render_template("ola.html", nome=request.args.get("nome"))


@app.route("/eco")
def eco():
    return {"mensagem": html.escape(request.args.get("msg", ""))}


@app.route("/sessao", methods=["POST"])
def sessao():
    estado = json.loads(request.get_data())
    return {"estado": estado}


@app.route("/config", methods=["POST"])
def importar_config():
    cfg = yaml.safe_load(request.data)
    return {"chaves": list(cfg)}


@app.route("/login")
def login():
    proxima = request.args.get("next", "")
    if not proxima.startswith("/") or proxima.startswith("//"):
        proxima = url_for("ola")
    return redirect(url_for("ola"))


@app.route("/admin/apagar")
def apagar():
    if request.headers.get("X-User-Role") != "admin":
        abort(403)
    return "apagado"


def hash_arquivo(conteudo: bytes) -> str:
    return hashlib.sha256(conteudo).hexdigest()


def checksum_legado(conteudo: bytes) -> str:
    return hashlib.md5(conteudo, usedforsecurity=False).hexdigest()


def gerar_token_reset() -> str:
    return secrets.token_urlsafe(32)


def ordenar_aleatorio(itens):
    import random

    embaralhado = random.sample(itens, len(itens))
    return embaralhado


def mensagem_erro_senha():
    erro = "A password deve ter pelo menos 12 caracteres e um símbolo"
    return erro


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), debug=os.getenv("FLASK_DEBUG") == "1")
