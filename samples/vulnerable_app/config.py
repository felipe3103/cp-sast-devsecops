"""Configuração com segredos hardcoded (vulnerável de propósito)."""
import hashlib
import random
import tempfile

import jwt
import requests
from Crypto.Cipher import AES, DES

DB_PASSWORD = "Sup3rS3nh@2024"  # expect: PY001
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # expect: PY001
API_TOKEN = "TODO"  # placeholder: não deve ser reportado
DATABASE = {"host": "db.interno", "password": "pr0d-p4ss!"}  # expect: PY001


def get_db_path():
    return "/var/lib/app/dados.db"


def hash_senha(senha):
    return hashlib.md5(senha.encode()).hexdigest()  # expect: PY006


def gerar_token_reset():
    token = random.randint(100000, 999999)  # expect: PY007
    return str(token)


def arquivo_temporario():
    return tempfile.mktemp(suffix=".csv")  # expect: PY011


def cifrar(chave, dados):
    legado = DES.new(chave[:8], DES.MODE_ECB)  # expect: PY012
    moderno = AES.new(chave, AES.MODE_ECB)  # expect: PY012
    return legado.encrypt(dados), moderno.encrypt(dados)


def ler_token(token):
    return jwt.decode(token, options={"verify_signature": False})  # expect: PY013


def consultar_api_interna(url):
    return requests.get(url, verify=False)  # expect: PY008 PY017


def checar_senha_admin(senha):
    if senha == "admin@123":  # expect: PY001
        return True
    return False
