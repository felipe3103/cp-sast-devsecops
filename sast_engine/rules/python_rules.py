"""Regras determinísticas e heurísticas para Python (inspeção estrutural da AST)."""
from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..languages.python_ast import (
    PythonModule,
    get_kwarg,
    is_constant_str,
    is_dynamic_string,
    is_false,
    is_literal,
    is_true,
    target_names,
)
from ..models import Confidence, Finding, Severity
from .base import make_finding, python_rule
from .secrets import is_secret_name, looks_like_secret_value, match_known_pattern

# =================================================================== PY001
def _secret_finding(module: PythonModule, node: ast.AST, name: str, value: str) -> Finding | None:
    label = match_known_pattern(value)
    if label:
        return make_finding(
            "PY001", module, node, f"{label} hardcoded em '{name}'.",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        )
    if is_secret_name(name) and looks_like_secret_value(value):
        return make_finding("PY001", module, node, f"Valor literal atribuído a '{name}', que parece ser uma credencial.")
    return None


@python_rule("PY001", ast.Assign, ast.AnnAssign)
def hardcoded_secret_assign(node, module: PythonModule) -> Iterator[Finding]:
    value = node.value
    if not is_constant_str(value):
        return
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        for name in target_names(target):
            finding = _secret_finding(module, node, name, value.value)
            if finding:
                yield finding
                return


@python_rule("PY001", ast.Call)
def hardcoded_secret_kwarg(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    for kw in node.keywords:
        if kw.arg and is_constant_str(kw.value):
            finding = _secret_finding(module, node, kw.arg, kw.value.value)
            if finding:
                yield finding
                return


@python_rule("PY001", ast.Dict)
def hardcoded_secret_dict(node: ast.Dict, module: PythonModule) -> Iterator[Finding]:
    for key, value in zip(node.keys, node.values):
        if is_constant_str(key) and is_constant_str(value):
            finding = _secret_finding(module, value, key.value, value.value)
            if finding:
                yield finding


@python_rule("PY001", ast.Compare)
def hardcoded_secret_compare(node: ast.Compare, module: PythonModule) -> Iterator[Finding]:
    """`if password == "admin123":` também é credencial hardcoded."""
    if len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
        return
    left, right = node.left, node.comparators[0]
    for name_node, value_node in ((left, right), (right, left)):
        if isinstance(name_node, (ast.Name, ast.Attribute)) and is_constant_str(value_node):
            finding = _secret_finding(module, node, ast.unparse(name_node), value_node.value)
            if finding:
                yield finding
                return


@python_rule("PY001", ast.Call)
def hardcoded_secret_env_default(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    """`os.getenv("DB_PASSWORD", "s3nh@")`: o segredo continua no código como fallback."""
    if module.call_name(node) not in {"os.getenv", "os.environ.get", "os.environ.setdefault"}:
        return
    if len(node.args) >= 2 and is_constant_str(node.args[0]) and is_constant_str(node.args[1]):
        name, default = node.args[0].value, node.args[1].value
        if is_secret_name(name) and looks_like_secret_value(default):
            yield make_finding("PY001", module, node, f"Segredo literal usado como valor padrão de '{name}'.")


# =================================================================== PY002
@python_rule("PY002", ast.Call)
def eval_exec(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if name not in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        return
    if node.args and is_literal(node.args[0]):
        yield make_finding(
            "PY002", module, node, f"{name}() com argumento constante; prefira código explícito.",
            severity=Severity.LOW,
        )
    else:
        yield make_finding("PY002", module, node, f"{name}() com argumento dinâmico pode executar código arbitrário.")


# =================================================================== PY003
SHELL_FUNCS = {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}
SUBPROCESS_FUNCS = {
    "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_call",
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
}


@python_rule("PY003", ast.Call)
def shell_command(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    first = node.args[0] if node.args else None
    if name in SHELL_FUNCS or name in {"subprocess.getoutput", "subprocess.getstatusoutput"}:
        if first is not None and not is_literal(first):
            yield make_finding("PY003", module, node, f"{name}() executa a string em um shell com valor dinâmico.")
        return
    if name in SUBPROCESS_FUNCS and is_true(get_kwarg(node, "shell")):
        if first is not None and is_literal(first):
            yield make_finding(
                "PY003", module, node, f"{name}(shell=True) com comando fixo.",
                severity=Severity.LOW, confidence=Confidence.HIGH,
            )
        else:
            yield make_finding("PY003", module, node, f"{name}(shell=True) com comando dinâmico.")


# =================================================================== PY004
@python_rule("PY004", ast.Call)
def insecure_deserialization(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if name in {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "marshal.loads",
                "marshal.load", "shelve.open", "dill.loads", "jsonpickle.decode", "pandas.read_pickle"}:
        yield make_finding("PY004", module, node, f"{name}() pode executar código ao desserializar.")
    elif name in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.full_load"}:
        loader = get_kwarg(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
        loader_name = module.qualname(loader) if loader is not None else ""
        if name == "yaml.unsafe_load" or not loader_name.endswith(("SafeLoader", "CSafeLoader", "BaseLoader")):
            yield make_finding("PY004", module, node, f"{name}() sem SafeLoader permite instanciar objetos Python.")


# =================================================================== PY005
SQL_KEYWORDS = re.compile(r"\b(select\s.+\sfrom|insert\s+into|update\s.+\sset|delete\s+from|drop\s+table|where\s)", re.I | re.S)
SQL_EXEC_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "text"}


SAFE_CASTS = {"int", "float", "bool", "len", "round", "abs"}


def _interpolated(node: ast.AST) -> list[ast.AST]:
    """Expressões inseridas dinamicamente na string (partes não constantes)."""
    if isinstance(node, ast.JoinedStr):
        return [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod) and is_constant_str(node.left):
            right = node.right
            return list(right.elts) if isinstance(right, ast.Tuple) else [right]
        return [p for side in (node.left, node.right) for p in (_interpolated(side) if isinstance(side, (ast.BinOp, ast.JoinedStr)) else [side])]
    if isinstance(node, ast.Call):
        return list(node.args) + [kw.value for kw in node.keywords]
    return [node]


def _only_safe_values(node: ast.AST, module: PythonModule) -> bool:
    """Todos os valores interpolados são constantes ou conversões numéricas (int(), float()...)."""
    for part in _interpolated(node):
        if isinstance(part, ast.Constant):
            continue
        if isinstance(part, ast.Call) and module.call_name(part) in SAFE_CASTS:
            continue
        return False
    return True


def _string_parts(node: ast.AST) -> str:
    """Concatena as partes constantes de uma string dinâmica para identificar SQL."""
    return " ".join(
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


@python_rule("PY005", ast.Call)
def sql_string_building(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    func = node.func
    method = func.attr if isinstance(func, ast.Attribute) else module.call_name(node).rsplit(".", 1)[-1]
    if method not in SQL_EXEC_METHODS or not node.args:
        return
    query = node.args[0]
    if is_dynamic_string(query) and SQL_KEYWORDS.search(_string_parts(query)) and not _only_safe_values(query, module):
        yield make_finding("PY005", module, node, f"Consulta SQL montada dinamicamente e passada para {method}().")


# =================================================================== PY006
WEAK_HASHES = {"md5", "sha1", "md4", "md2"}


@python_rule("PY006", ast.Call)
def weak_hash(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if is_false(get_kwarg(node, "usedforsecurity")):
        return
    algo = None
    if name.startswith("hashlib.") and name.split(".", 1)[1] in WEAK_HASHES:
        algo = name.split(".", 1)[1]
    elif name == "hashlib.new" and node.args and is_constant_str(node.args[0]):
        if node.args[0].value.lower() in WEAK_HASHES:
            algo = node.args[0].value.lower()
    elif name.startswith(("Crypto.Hash.MD5", "Crypto.Hash.SHA1", "Cryptodome.Hash.MD5")):
        algo = name.split(".")[2]
    if algo:
        yield make_finding("PY006", module, node, f"Uso de {algo.upper()}, algoritmo de hash quebrado.")


# =================================================================== PY007
RANDOM_FUNCS = {"random.random", "random.randint", "random.choice", "random.choices",
                "random.randrange", "random.getrandbits", "random.sample", "random.uniform"}
SECURITY_CONTEXT = re.compile(r"(token|senha|password|passwd|secret|otp|nonce|salt|session|csrf|api_?key|reset|codigo|code)", re.I)


@python_rule("PY007", ast.Call)
def weak_random(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    if module.call_name(node) not in RANDOM_FUNCS:
        return
    # sobe até a atribuição ou definição de função para descobrir o contexto
    current: ast.AST | None = node
    while current is not None and not isinstance(current, (ast.Assign, ast.AnnAssign, ast.Return, ast.FunctionDef)):
        current = module.parent(current)
    context = ""
    if isinstance(current, (ast.Assign, ast.AnnAssign)):
        targets = current.targets if isinstance(current, ast.Assign) else [current.target]
        context = " ".join(n for t in targets for n in target_names(t))
    elif current is not None:
        func = current if isinstance(current, ast.FunctionDef) else module.parent(current)
        while func is not None and not isinstance(func, ast.FunctionDef):
            func = module.parent(func)
        context = func.name if func is not None else ""
    if SECURITY_CONTEXT.search(context):
        yield make_finding("PY007", module, node, f"random usado para gerar '{context}'; use o módulo secrets.")


# =================================================================== PY008
HTTP_LIBS = ("requests.", "httpx.", "aiohttp.")


@python_rule("PY008", ast.Call)
def tls_verify_disabled(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if is_false(get_kwarg(node, "verify")) and (name.startswith(HTTP_LIBS) or "session" in name.lower() or "client" in name.lower()):
        yield make_finding("PY008", module, node, f"{name}(verify=False) aceita qualquer certificado.")
    elif name in {"ssl._create_unverified_context"}:
        yield make_finding("PY008", module, node, "Contexto SSL sem verificação de certificado.")


# =================================================================== PY009
@python_rule("PY009", ast.Call)
def debug_enabled(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    if isinstance(node.func, ast.Attribute) and node.func.attr == "run" and is_true(get_kwarg(node, "debug")):
        yield make_finding("PY009", module, node, "Aplicação iniciada com debug=True.")


@python_rule("PY009", ast.Assign)
def django_debug(node: ast.Assign, module: PythonModule) -> Iterator[Finding]:
    if is_true(node.value) and any(n == "DEBUG" for t in node.targets for n in target_names(t)):
        if module.path.endswith("settings.py"):
            yield make_finding("PY009", module, node, "DEBUG = True em settings do Django.")


# =================================================================== PY010
AUTH_WORDS = re.compile(r"(admin|auth|permission|permiss|role|is_staff|is_superuser|logged|owner|allowed)", re.I)


@python_rule("PY010", ast.Assert)
def assert_security(node: ast.Assert, module: PythonModule) -> Iterator[Finding]:
    if "test" in module.path.rsplit("/", 1)[-1]:
        return
    if AUTH_WORDS.search(ast.unparse(node.test)):
        yield make_finding("PY010", module, node, "assert usado em checagem de autorização é removido com python -O.")


# =================================================================== PY011
@python_rule("PY011", ast.Call)
def insecure_tempfile(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    if module.call_name(node) == "tempfile.mktemp":
        yield make_finding("PY011", module, node, "tempfile.mktemp() é vulnerável a race condition.")


# =================================================================== PY012
WEAK_CIPHERS = ("DES", "DES3", "ARC4", "ARC2", "Blowfish", "TripleDES", "IDEA", "CAST5")


@python_rule("PY012", ast.Call, ast.Attribute)
def weak_cipher(node, module: PythonModule) -> Iterator[Finding]:
    if isinstance(node, ast.Call):
        name = module.call_name(node)
        parts = name.split(".")
        if any(p in WEAK_CIPHERS for p in parts[-2:]) and ("Crypto" in name or "cryptography" in name or "algorithms" in name):
            yield make_finding("PY012", module, node, f"Cifra fraca: {name}.")
    else:  # modes.ECB / AES.MODE_ECB
        if node.attr in {"MODE_ECB", "ECB"} and not isinstance(module.parent(node), ast.Attribute):
            yield make_finding("PY012", module, node, "Modo ECB não esconde padrões do texto claro.")


# =================================================================== PY013
@python_rule("PY013", ast.Call)
def jwt_no_verify(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if not name.startswith(("jwt.", "jose.jwt.")) or not name.endswith("decode"):
        return
    if is_false(get_kwarg(node, "verify")):
        yield make_finding("PY013", module, node, "jwt.decode com verify=False.")
        return
    options = get_kwarg(node, "options")
    if isinstance(options, ast.Dict):
        for k, v in zip(options.keys, options.values):
            if is_constant_str(k) and k.value == "verify_signature" and is_false(v):
                yield make_finding("PY013", module, node, "jwt.decode com verify_signature desabilitado.")
                return
    algorithms = get_kwarg(node, "algorithms")
    if algorithms is not None and "none" in ast.unparse(algorithms).lower():
        yield make_finding("PY013", module, node, "jwt.decode aceita o algoritmo 'none'.")


# =================================================================== PY014
@python_rule("PY014", ast.Call)
def permissive_chmod(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if name not in {"os.chmod", "os.fchmod", "os.lchmod"} and not name.endswith(".chmod"):
        return
    mode = node.args[1] if name.startswith("os.") and len(node.args) > 1 else (node.args[0] if node.args else get_kwarg(node, "mode"))
    if isinstance(mode, ast.Constant) and isinstance(mode.value, int) and mode.value & 0o002:
        yield make_finding("PY014", module, node, f"Permissão {oct(mode.value)} permite escrita por qualquer usuário.")


# =================================================================== PY015
@python_rule("PY015", ast.Call)
def jinja_autoescape(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if name in {"jinja2.Environment", "jinja2.Template"}:
        autoescape = get_kwarg(node, "autoescape")
        if (autoescape is None and name == "jinja2.Environment") or is_false(autoescape):
            yield make_finding("PY015", module, node, "Jinja2 configurado sem autoescape.")


# =================================================================== PY016
XML_UNSAFE = {
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.etree.cElementTree.parse",
    "xml.etree.cElementTree.fromstring", "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
    "xml.sax.parse", "xml.sax.parseString", "lxml.etree.parse", "lxml.etree.fromstring", "lxml.etree.XML",
}


@python_rule("PY016", ast.Call)
def xxe(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if name in XML_UNSAFE:
        yield make_finding("PY016", module, node, f"{name}() não protege contra XXE/billion laughs.")


# =================================================================== PY017
@python_rule("PY017", ast.Call)
def no_timeout(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    name = module.call_name(node)
    if name in {f"requests.{m}" for m in ("get", "post", "put", "patch", "delete", "head", "options", "request")}:
        if get_kwarg(node, "timeout") is None and not any(kw.arg is None for kw in node.keywords):
            yield make_finding("PY017", module, node, f"{name}() sem timeout.")


# =================================================================== PY018
@python_rule("PY018", ast.Call)
def bind_all(node: ast.Call, module: PythonModule) -> Iterator[Finding]:
    host = get_kwarg(node, "host")
    # literal procurado pela própria regra, não é um bind
    if is_constant_str(host) and host.value == "0.0.0.0":  # nosec B104
        yield make_finding("PY018", module, node, "Serviço escutando em 0.0.0.0 (todas as interfaces).")
