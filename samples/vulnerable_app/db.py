"""Camada de dados vulnerável (sinks alcançados a partir de app.py)."""
import sqlite3

from config import get_db_path


def _conexao():
    return sqlite3.connect(get_db_path())


def montar_filtro(campo, valor):
    return campo + " = '" + valor + "'"


def buscar_usuario_por_nome(nome):
    cur = _conexao().cursor()
    sql = "SELECT id, nome FROM usuarios WHERE " + montar_filtro("nome", nome)
    cur.execute(sql)  # expect: TAINT-SQLI
    return cur.fetchone()


def executar_relatorio(ano, mes):
    cur = _conexao().cursor()
    # ano é convertido por <int:ano> na rota, mas mes é texto livre
    cur.execute("SELECT * FROM vendas WHERE ano = %d AND mes = '%s'" % (ano, mes))  # expect: TAINT-SQLI
    return cur.fetchall()
