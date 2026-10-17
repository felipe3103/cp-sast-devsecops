"""Heurísticas para detecção de segredos hardcoded.

Duas estratégias combinadas para manter baixo o índice de falsos positivos:
1. Padrões de formato conhecido (chave AWS, token GitHub, chave privada...) -> alta confiança.
2. Nome da variável sugere segredo (password, api_key...) E o valor parece um
   segredo real (não é placeholder, não é vazio, tem comprimento/entropia mínimos).
"""
from __future__ import annotations

import math
import re

KNOWN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Chave de acesso AWS", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Token GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Token Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Chave de API Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Chave secreta Stripe", re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{20,}\b")),
    ("Chave privada", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("URL com credencial", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]{3,}@[^\s/]+")),
]

SECRET_NAME = re.compile(
    r"(pass(word|wd)?|pwd|senha|secret|segredo|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?key|credential|conn(ection)?[_-]?str)",
    re.IGNORECASE,
)

# Nomes que contêm "token"/"password" mas não guardam o segredo em si.
NON_SECRET_NAME = re.compile(
    r"(_url|_uri|_endpoint|_path|_file|_field|_name|_label|_len(gth)?|_header|_type|"
    r"_param|_key_name|_policy|_regex|_pattern|^token_type$|_prefix|_env|_var|_hint|"
    r"_min|_max|_count|_expire|_ttl|_timeout)$",
    re.IGNORECASE,
)

PLACEHOLDERS = re.compile(
    r"^(|x+|\*+|\.+|-+|changeme|change[_-]?me|todo|tbd|none|null|nil|test|testing|example|"
    r"sample|dummy|fake|placeholder|your[_-].*|<.*>|\{.*\}|\$\{.*\}|%\(.*\)s|xxx.*|secret|"
    r"password|senha|token|redacted|\*\*\*.*)$",
    re.IGNORECASE,
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in freq.values())


def match_known_pattern(value: str) -> str | None:
    for label, pattern in KNOWN_PATTERNS:
        if pattern.search(value):
            return label
    return None


def is_secret_name(name: str) -> bool:
    simple = name.rsplit(".", 1)[-1].strip("_")
    return bool(SECRET_NAME.search(simple)) and not NON_SECRET_NAME.search(simple)


def looks_like_secret_value(value: str) -> bool:
    value = value.strip()
    if PLACEHOLDERS.match(value):
        return False
    if len(value) < 6 or " " in value.strip() and len(value.split()) > 3:
        return False  # frases/mensagens não são credenciais
    if value.startswith(("http://", "https://", "/", "./")) and not match_known_pattern(value):
        return False
    return shannon_entropy(value) >= 2.5
