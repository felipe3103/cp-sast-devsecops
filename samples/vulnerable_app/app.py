"""Aplicação Flask INTENCIONALMENTE VULNERÁVEL, escrita pelo grupo para testes do SAST.

Cada linha vulnerável tem um comentário `# expect: <REGRA>` usado pelo benchmark
(benchmark/run_benchmark.py) para medir precisão e recall do motor.
NÃO usar em produção.
"""
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, Markup, redirect, render_template_string, request

from config import get_db_path
from db import buscar_usuario_por_nome, executar_relatorio

app = Flask(__name__)
app.secret_key = "k8$Lq2!vR9@pXw7#nZ"  # expect: PY001

UPLOAD_DIR = "/srv/uploads"


@app.route("/usuario")
def usuario():
    nome = request.args.get("nome", "")
    conn = sqlite3.connect(get_db_path())
    query = f"SELECT * FROM usuarios WHERE nome = '{nome}'"
    rows = conn.execute(query).fetchall()  # expect: TAINT-SQLI
    return {"usuarios": rows}


@app.route("/usuario/v2")
def usuario_v2():
    # o sink está em outro arquivo (db.py): taint interprocedural entre módulos
    return {"usuario": buscar_usuario_por_nome(request.args["nome"])}


@app.route("/relatorio/<int:ano>/<mes>")
def relatorio(ano, mes):
    return {"linhas": executar_relatorio(ano, mes)}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    saida = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # expect: TAINT-CMDI
    return saida


@app.route("/backup")
def backup():
    destino = request.form["destino"]
    os.system("tar czf /tmp/backup.tgz " + destino)  # expect: TAINT-CMDI
    return "ok"


@app.route("/calc")
def calc():
    expressao = request.args.get("expr")
    resultado = eval(expressao)  # expect: TAINT-CODE
    return str(resultado)


@app.route("/arquivo")
def arquivo():
    nome = request.args.get("nome")
    caminho = os.path.join(UPLOAD_DIR, nome)
    with open(caminho) as fp:  # expect: TAINT-PATH
        return fp.read()


@app.route("/preview")
def preview():
    url = request.args.get("url")
    resposta = requests.get(url, timeout=5)  # expect: TAINT-SSRF
    return resposta.text


@app.route("/ola")
def ola():
    nome = request.args.get("nome", "visitante")
    return f"<h1>Olá, {nome}!</h1>"  # expect: TAINT-XSS


@app.route("/saudacao")
def saudacao():
    nome = request.args.get("nome", "")
    return render_template_string("<p>Bem-vindo " + nome + "</p>")  # expect: TAINT-XSS


@app.route("/banner")
def banner():
    texto = request.cookies.get("banner")
    return Markup(texto)  # expect: TAINT-XSS


@app.route("/sessao", methods=["POST"])
def sessao():
    dados = request.get_data()
    estado = pickle.loads(dados)  # expect: TAINT-DESER
    return {"estado": str(estado)}


@app.route("/config", methods=["POST"])
def importar_config():
    cfg = yaml.load(request.data)  # expect: TAINT-DESER
    return {"chaves": list(cfg)}


@app.route("/login")
def login():
    proxima = request.args.get("next")
    return redirect(proxima)  # expect: TAINT-REDIRECT


@app.route("/admin/apagar")
def apagar():
    usuario_logado = request.headers.get("X-User-Role")
    assert usuario_logado == "admin"  # expect: PY010
    return "apagado"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # expect: PY009 PY018
