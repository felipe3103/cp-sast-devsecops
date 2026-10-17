"""Utilitários com padrões inseguros detectáveis sem taint (regras estruturais)."""
import os
import subprocess
import xml.etree.ElementTree as ET

import yaml
from jinja2 import Environment, FileSystemLoader


def executar(comando):
    return subprocess.run(comando, shell=True, capture_output=True)  # expect: PY003


def limpar_cache(pasta):
    os.system("rm -rf " + pasta)  # expect: PY003


def interpretar(expr):
    return eval(expr)  # expect: PY002


def carregar_yaml(caminho):
    with open(caminho) as fp:
        return yaml.load(fp, Loader=yaml.Loader)  # expect: PY004


def ler_xml(conteudo):
    return ET.fromstring(conteudo)  # expect: PY016


def publicar(caminho):
    os.chmod(caminho, 0o777)  # expect: PY014


def ambiente_templates():
    return Environment(loader=FileSystemLoader("templates"))  # expect: PY015


def contar_pedidos(cursor, cliente):
    cursor.execute(f"SELECT COUNT(*) FROM pedidos WHERE cliente = '{cliente}'")  # expect: PY005
    return cursor.fetchone()[0]
