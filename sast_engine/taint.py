"""Taint analysis para Python.

Rastreia o fluxo de dados não confiáveis (sources) até funções sensíveis (sinks).

Características:
- Sensível ao fluxo: reatribuir uma variável com valor limpo remove a contaminação.
- Interprocedural: cada função ganha um *resumo* (quais parâmetros chegam ao retorno
  e quais chegam a sinks). Os resumos são recalculados até um ponto fixo, inclusive
  entre arquivos do mesmo projeto (`from utils import helper`).
- Sanitizadores (int(), shlex.quote, html.escape, secure_filename...) e guardas de
  saída antecipada (`if not nome.isalnum(): abort(400)`) removem a contaminação,
  reduzindo falsos positivos.
- Cada achado carrega o caminho completo fonte -> propagação -> sink (trace).
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .languages.python_ast import (
    PythonModule,
    get_kwarg,
    is_constant_str,
    is_true,
    target_names,
)
from .models import Confidence, Finding, TraceStep
from .rules.catalog import CATALOG

SOURCE = "SOURCE"
MAX_TRACE = 10

# ------------------------------------------------------------------ fontes
REQUEST_ATTRS = {
    "args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST",
    "body", "query_params", "path_params", "COOKIES", "META", "get_json", "get_data", "stream",
    "FILES", "query_string", "view_args",
}
SOURCE_CALLS = {"input", "raw_input", "sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines"}
SOURCE_ATTRS = {"sys.argv"}

ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket", "api_view"}
NON_INPUT_PARAMS = {"self", "cls", "request", "db", "session", "background_tasks", "response"}

# ------------------------------------------------------------ sanitizadores
SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "ord", "hash", "uuid.UUID", "decimal.Decimal",
    "shlex.quote", "pipes.quote", "html.escape", "markupsafe.escape", "flask.escape", "cgi.escape",
    "bleach.clean", "jinja2.escape", "django.utils.html.escape", "werkzeug.utils.secure_filename",
    "os.path.basename", "re.escape", "urllib.parse.quote", "urllib.parse.quote_plus",
    "hashlib.sha256", "hashlib.sha512", "secrets.compare_digest", "hmac.compare_digest",
    "isinstance", "callable", "id", "type", "datetime.date.fromisoformat", "ipaddress.ip_address",
}
SANITIZER_SUFFIXES = (".isdigit", ".isalnum", ".isnumeric", ".isidentifier", ".hexdigest", ".count", ".startswith", ".endswith")

# ------------------------------------------------------------------- sinks
@dataclass(frozen=True)
class Sink:
    rule_id: str
    label: str
    arg: int = 0
    kwarg: str | None = None


def _sinks() -> dict[str, Sink]:
    sinks: dict[str, Sink] = {}
    for name in ("eval", "exec", "compile", "builtins.eval", "builtins.exec"):
        sinks[name] = Sink("TAINT-CODE", name)
    for name in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"):
        sinks[name] = Sink("TAINT-CMDI", name)
    for name in ("open", "builtins.open", "io.open", "os.open", "os.remove", "os.unlink", "os.rmdir",
                 "os.listdir", "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.move",
                 "flask.send_file", "codecs.open", "tarfile.open", "zipfile.ZipFile"):
        sinks[name] = Sink("TAINT-PATH", name, kwarg="file" if "open" in name else None)
    for lib in ("requests", "httpx"):
        for m in ("get", "post", "put", "patch", "delete", "head", "options"):
            sinks[f"{lib}.{m}"] = Sink("TAINT-SSRF", f"{lib}.{m}", kwarg="url")
        sinks[f"{lib}.request"] = Sink("TAINT-SSRF", f"{lib}.request", arg=1, kwarg="url")
    for name in ("urllib.request.urlopen", "urllib.urlopen", "urllib2.urlopen", "urllib.request.Request"):
        sinks[name] = Sink("TAINT-SSRF", name, kwarg="url")
    for name in ("flask.render_template_string", "jinja2.Template", "markupsafe.Markup", "flask.Markup",
                 "django.utils.safestring.mark_safe", "fastapi.responses.HTMLResponse",
                 "starlette.responses.HTMLResponse", "flask.make_response", "django.http.HttpResponse"):
        sinks[name] = Sink("TAINT-XSS", name, kwarg="content" if "Response" in name else None)
    for name in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "yaml.load",
                 "yaml.unsafe_load", "yaml.full_load", "jsonpickle.decode", "dill.loads"):
        sinks[name] = Sink("TAINT-DESER", name)
    for name in ("flask.redirect", "django.shortcuts.redirect", "django.http.HttpResponseRedirect",
                 "fastapi.responses.RedirectResponse", "starlette.responses.RedirectResponse"):
        sinks[name] = Sink("TAINT-REDIRECT", name, kwarg="url")
    sinks["sqlalchemy.text"] = Sink("TAINT-SQLI", "sqlalchemy.text")
    return sinks


SINKS = _sinks()
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "mogrify"}
SUBPROCESS = {"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
EXACT_PROPAGATORS = {
    "str", "repr", "format", "list", "dict", "tuple", "set", "bytes", "sorted", "reversed",
    "os.path.join", "os.path.normpath", "os.path.abspath", "os.path.realpath", "pathlib.Path",
    "urllib.parse.urljoin", "base64.b64decode", "json.loads", "json.dumps",
}
MUTATORS = {"append", "extend", "insert", "add", "update", "setdefault", "appendleft", "extendleft"}
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir"}


# =================================================================== Taint
@dataclass(frozen=True)
class Taint:
    origins: frozenset[str]
    trace: tuple[TraceStep, ...] = ()
    approx: bool = False  # passou por função desconhecida -> confiança menor

    @property
    def is_source(self) -> bool:
        return SOURCE in self.origins

    def params(self) -> set[int]:
        return {int(o.split(":", 1)[1]) for o in self.origins if o.startswith("param:")}

    def step(self, line: int, description: str, file: str = "") -> "Taint":
        if self.trace and self.trace[-1].line == line and self.trace[-1].description == description:
            return self
        trace = self.trace + (TraceStep(line, description, file),)
        if len(trace) > MAX_TRACE:
            trace = trace[:2] + trace[-(MAX_TRACE - 2):]
        return Taint(self.origins, trace, self.approx)

    def only(self, origin: str) -> "Taint":
        return Taint(frozenset({origin}), self.trace, self.approx)

    def with_approx(self) -> "Taint":
        return Taint(self.origins, self.trace, True)


def union(*items: Taint | None) -> Taint | None:
    present = [t for t in items if t is not None]
    if not present:
        return None
    if len(present) == 1:
        return present[0]
    origins = frozenset().union(*(t.origins for t in present))
    best = next((t for t in present if t.is_source), present[0])
    return Taint(origins, best.trace, any(t.approx for t in present))


def merge_states(*states: dict[str, Taint]) -> dict[str, Taint]:
    merged: dict[str, Taint] = {}
    for key in set().union(*states):
        merged[key] = union(*(s.get(key) for s in states))
    return merged


# ======================================================== funções e resumos
@dataclass
class SinkHit:
    rule_id: str
    module: PythonModule
    line: int
    message: str
    trace: tuple[TraceStep, ...]


@dataclass
class Summary:
    returns_params: set[int] = field(default_factory=set)
    returns_source: Taint | None = None
    sink_params: dict[int, list[SinkHit]] = field(default_factory=dict)

    def signature(self) -> tuple:
        return (
            frozenset(self.returns_params),
            self.returns_source is not None,
            frozenset((i, h.rule_id, h.line) for i, hits in self.sink_params.items() for h in hits),
        )


@dataclass
class FunctionInfo:
    key: str
    name: str
    node: ast.AST
    module: PythonModule
    module_name: str
    params: list[str]
    is_method: bool
    route: str | None  # "flask" | "fastapi" | None
    summary: Summary = field(default_factory=Summary)


def _decorator_route(func: ast.FunctionDef, module: PythonModule) -> str | None:
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
            if any(v.startswith("fastapi") for v in module.imports.values()):
                return "fastapi"
            return "flask"
        if isinstance(target, ast.Name) and target.id == "api_view":
            return "django"
    return None


def _module_name(path: str) -> str:
    name = path[:-3] if path.endswith(".py") else path
    name = name.replace("\\", "/").strip("./").replace("/", ".")
    return name[: -len(".__init__")] if name.endswith(".__init__") else name


# ================================================================== engine
class TaintEngine:
    """Executa a análise de taint sobre um conjunto de módulos (um projeto)."""

    MAX_ITERATIONS = 8

    def __init__(self, modules: list[PythonModule]):
        self.modules = modules
        self.functions: dict[str, FunctionInfo] = {}
        self.by_module: dict[str, dict[str, list[FunctionInfo]]] = {}
        self.findings: dict[tuple, Finding] = {}
        for module in modules:
            self._collect(module)

    # ------------------------------------------------------------- coleta
    def _collect(self, module: PythonModule) -> None:
        mod_name = _module_name(module.path)
        table = self.by_module.setdefault(mod_name, {})

        def visit(body: list[ast.stmt], prefix: str, in_class: bool) -> None:
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                    info = FunctionInfo(
                        key=f"{mod_name}:{prefix}{node.name}", name=node.name, node=node, module=module,
                        module_name=mod_name, params=params,
                        is_method=in_class and bool(params) and params[0] in {"self", "cls"},
                        route=_decorator_route(node, module),
                    )
                    self.functions[info.key] = info
                    table.setdefault(node.name, []).append(info)
                    visit(node.body, f"{prefix}{node.name}.", False)
                elif isinstance(node, ast.ClassDef):
                    visit(node.body, f"{prefix}{node.name}.", True)

        visit(module.tree.body, "", False)
        top = ast.Module(body=[s for s in module.tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))], type_ignores=[])
        self.functions[f"{mod_name}:<module>"] = FunctionInfo(
            key=f"{mod_name}:<module>", name="<module>", node=top, module=module,
            module_name=mod_name, params=[], is_method=False, route=None,
        )

    def resolve(self, caller: FunctionInfo, call: ast.Call) -> tuple[FunctionInfo | None, int]:
        """Encontra a função chamada no projeto. Retorna (função, deslocamento de argumentos)."""
        func = call.func
        if isinstance(func, ast.Name):
            local = self.by_module.get(caller.module_name, {}).get(func.id)
            if local:
                return local[0], 0
            target = caller.module.imports.get(func.id, "")
            if "." in target:
                mod, _, name = target.rpartition(".")
                for mod_name, table in self.by_module.items():
                    if (mod_name == mod or mod_name.endswith("." + mod)) and name in table:
                        return table[name][0], 0
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in {"self", "cls"}:
                for info in self.by_module.get(caller.module_name, {}).get(func.attr, []):
                    if info.is_method:
                        return info, 1
            target = caller.module.imports.get(func.value.id)
            if target:
                for mod_name, table in self.by_module.items():
                    if (mod_name == target or mod_name.endswith("." + target)) and func.attr in table:
                        return table[func.attr][0], 0
        return None, 0

    # ------------------------------------------------------------ execução
    def run(self) -> list[Finding]:
        for _ in range(self.MAX_ITERATIONS):
            before = {k: f.summary.signature() for k, f in self.functions.items()}
            for info in self.functions.values():
                FunctionAnalyzer(self, info, report=False).analyze()
            if before == {k: f.summary.signature() for k, f in self.functions.items()}:
                break
        for info in self.functions.values():
            FunctionAnalyzer(self, info, report=True).analyze()
        return list(self.findings.values())

    def report(self, hit: SinkHit, taint: Taint) -> None:
        meta = CATALOG[hit.rule_id]
        key = (hit.rule_id, hit.module.path, hit.line)
        if key in self.findings:
            return
        source_line = taint.trace[0].line if taint.trace else hit.line
        self.findings[key] = Finding(
            rule_id=hit.rule_id,
            title=meta.title,
            message=hit.message,
            file=hit.module.path,
            line=hit.line,
            severity=meta.severity,
            confidence=Confidence.MEDIUM if taint.approx else Confidence.HIGH,
            cwe=meta.cwe,
            owasp=meta.owasp,
            snippet=hit.module.snippet(hit.line),
            engine="sast-engine/taint",
            trace=list(taint.trace) + list(hit.trace),
            remediation=meta.remediation,
            extra={"source_line": source_line},
        )


class FunctionAnalyzer:
    def __init__(self, engine: TaintEngine, info: FunctionInfo, report: bool):
        self.engine = engine
        self.info = info
        self.module = info.module
        self.report_mode = report
        self.summary = Summary() if not report else info.summary
        self.state: dict[str, Taint] = {}

    # ----------------------------------------------------------- execução
    def analyze(self) -> None:
        node = self.info.node
        line = getattr(node, "lineno", 1)
        input_params = self._input_params()
        for i, name in enumerate(self.info.params):
            origins = {f"param:{i}"}
            desc = f"parâmetro '{name}' de {self.info.name}()"
            if name in input_params:
                origins.add(SOURCE)
                desc = f"fonte: parâmetro '{name}' da rota {self.info.name}() (entrada HTTP)"
            self.state[name] = Taint(frozenset(origins), (TraceStep(line, desc, self.module.path),))
        self.visit_block(node.body)
        if not self.report_mode:
            self.info.summary = self.summary

    def _input_params(self) -> set[str]:
        if not self.info.route or not isinstance(self.info.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return set()
        args = self.info.node.args
        defaults = dict(zip([a.arg for a in args.args][-len(args.defaults):] if args.defaults else [], args.defaults))
        defaults.update({a.arg: d for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None})
        names = set()
        for name in self.info.params:
            default = defaults.get(name)
            if name in NON_INPUT_PARAMS:
                continue
            if isinstance(default, ast.Call) and self.module.call_name(default).endswith(("Depends", "Security")):
                continue
            names.add(name)
        return names

    # ---------------------------------------------------------- statements
    def visit_block(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.visit_stmt(stmt)

    def visit_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # analisadas separadamente
        if isinstance(stmt, ast.Assign):
            taint = self.eval(stmt.value)
            for target in stmt.targets:
                self.assign(target, taint, stmt.lineno)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self.assign(stmt.target, self.eval(stmt.value), stmt.lineno)
        elif isinstance(stmt, ast.AugAssign):
            taint = union(self.eval(stmt.target), self.eval(stmt.value))
            self.assign(stmt.target, taint, stmt.lineno)
        elif isinstance(stmt, ast.Expr):
            self.eval(stmt.value)
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                taint = self.eval(stmt.value)
                if taint is not None:
                    self.summary.returns_params |= taint.params()
                    if taint.is_source and self.summary.returns_source is None:
                        self.summary.returns_source = taint.step(stmt.lineno, f"retornado por {self.info.name}()", self.module.path)
                    self._check_html_return(stmt, taint)
        elif isinstance(stmt, ast.If):
            self.visit_if(stmt)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_taint = self.eval(stmt.iter)
            before = dict(self.state)
            for _ in range(2):  # duas passadas aproximam o ponto fixo do laço
                self.assign(stmt.target, iter_taint, stmt.lineno)
                self.visit_block(stmt.body)
            self.state = merge_states(before, self.state)
            self.visit_block(stmt.orelse)
        elif isinstance(stmt, ast.While):
            self.eval(stmt.test)
            before = dict(self.state)
            for _ in range(2):
                self.visit_block(stmt.body)
            self.state = merge_states(before, self.state)
            self.visit_block(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                taint = self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, taint, stmt.lineno)
            self.visit_block(stmt.body)
        elif isinstance(stmt, ast.Try) or (hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)):
            before = dict(self.state)
            self.visit_block(stmt.body)
            after_body = dict(self.state)
            states = [after_body]
            for handler in stmt.handlers:
                self.state = merge_states(before, after_body)
                self.visit_block(handler.body)
                states.append(self.state)
            self.state = merge_states(*states)
            self.visit_block(stmt.orelse)
            self.visit_block(stmt.finalbody)
        elif isinstance(stmt, ast.Match):
            self.eval(stmt.subject)
            before = dict(self.state)
            branches = []
            for case in stmt.cases:
                self.state = dict(before)
                self.visit_block(case.body)
                branches.append(self.state)
            self.state = merge_states(before, *branches)
        elif isinstance(stmt, (ast.Raise, ast.Assert, ast.Delete)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self.eval(child)

    def visit_if(self, stmt: ast.If) -> None:
        self.eval(stmt.test)
        before = dict(self.state)
        positive, negative = self._guards(stmt.test)
        for name in positive:  # dentro do if, a variável foi validada
            self.state.pop(name, None)
        self.visit_block(stmt.body)
        body_state = self.state
        self.state = dict(before)
        for name in negative:
            self.state.pop(name, None)
        self.visit_block(stmt.orelse)
        else_state = self.state
        if _exits(stmt.body):
            self.state = else_state
        elif stmt.orelse and _exits(stmt.orelse):
            self.state = body_state
        else:
            self.state = merge_states(body_state, else_state)

    def _guards(self, test: ast.expr) -> tuple[set[str], set[str]]:
        """Variáveis validadas pelo teste: (válidas no ramo if, válidas no ramo else)."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            pos, neg = self._guards(test.operand)
            return neg, pos
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            pos: set[str] = set()
            for value in test.values:
                pos |= self._guards(value)[0]
            return pos, set()
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.In, ast.NotIn)):
            # `x in PERMITIDOS` ou `urlparse(url).hostname not in PERMITIDOS` (allowlist)
            names = {n.id for n in ast.walk(test.left) if isinstance(n, ast.Name)} - {"self"}
            return (names, set()) if isinstance(test.ops[0], ast.In) else (set(), names)
        if isinstance(test, ast.Call):
            name = self.module.call_name(test)
            simple = name.rsplit(".", 1)[-1]
            validator = (
                simple in {"isdigit", "isalnum", "isnumeric", "isidentifier", "isdecimal", "fullmatch", "match", "is_relative_to"}
                or simple.startswith(("is_safe", "is_valid", "valid", "is_allowed", "allowed", "safe_", "check_"))
                or (simple == "startswith" and isinstance(test.func, ast.Attribute))
            )
            if validator:
                names = {n.id for arg in [test.func, *test.args] for n in ast.walk(arg) if isinstance(n, ast.Name)}
                return names - {"re", "os", "self"}, set()
        return set(), set()

    def assign(self, target: ast.AST, taint: Taint | None, line: int) -> None:
        if isinstance(target, ast.Subscript):
            # d[k] = valor contaminado -> d passa a conter dado contaminado (atualização fraca)
            base = target.value
            name = ast.unparse(base)
            if taint is not None:
                self.state[name] = union(self.state.get(name), taint.step(line, f"armazenado em {name}[...]", self.module.path))
            return
        for name in target_names(target):
            if taint is None:
                self.state.pop(name, None)
            else:
                self.state[name] = taint.step(line, f"atribuído a '{name}'", self.module.path)

    # ---------------------------------------------------------- expressões
    def eval(self, node: ast.AST | None) -> Taint | None:
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return self.state.get(node.id)
        if isinstance(node, ast.Attribute):
            qual = self.module.qualname(node)
            if self._is_source_attr(qual):
                return Taint(frozenset({SOURCE}), (TraceStep(node.lineno, f"fonte: {ast.unparse(node)}", self.module.path),))
            dotted = ast.unparse(node)
            if dotted in self.state:
                return self.state[dotted]
            return self.eval(node.value)
        if isinstance(node, ast.Subscript):
            self.eval(node.slice)
            return self.eval(node.value)
        if isinstance(node, ast.Call):
            return self.eval_call(node)
        if isinstance(node, ast.JoinedStr):
            return union(*(self.eval(v) for v in node.values))
        if isinstance(node, ast.FormattedValue):
            return self.eval(node.value)
        if isinstance(node, ast.BinOp):
            return union(self.eval(node.left), self.eval(node.right))
        if isinstance(node, ast.BoolOp):
            return union(*(self.eval(v) for v in node.values))
        if isinstance(node, ast.IfExp):
            self.eval(node.test)
            return union(self.eval(node.body), self.eval(node.orelse))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return union(*(self.eval(e) for e in node.elts))
        if isinstance(node, ast.Dict):
            return union(*(self.eval(v) for v in node.values), *(self.eval(k) for k in node.keys if k))
        if isinstance(node, (ast.Starred, ast.Await)):
            return self.eval(node.value)
        if isinstance(node, ast.NamedExpr):
            taint = self.eval(node.value)
            self.assign(node.target, taint, node.lineno)
            return taint
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            saved = dict(self.state)
            for gen in node.generators:
                self.assign(gen.target, self.eval(gen.iter), node.lineno)
                for cond in gen.ifs:
                    self.eval(cond)
            if isinstance(node, ast.DictComp):
                taint = union(self.eval(node.key), self.eval(node.value))
            else:
                taint = self.eval(node.elt)
            self.state = saved
            return taint
        if isinstance(node, (ast.Compare, ast.UnaryOp)):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.eval(child)
            return None  # resultado booleano/numérico não carrega o dado
        return None

    @staticmethod
    def _is_source_attr(qual: str) -> bool:
        if qual in SOURCE_ATTRS:
            return True
        parts = qual.split(".")
        for i, part in enumerate(parts[:-1]):
            if part == "request" and parts[i + 1] in REQUEST_ATTRS:
                return True
        return False

    def eval_call(self, call: ast.Call) -> Taint | None:
        name = self.module.call_name(call)
        line = call.lineno
        args = [self.eval(a) for a in call.args]
        kwargs = {kw.arg: self.eval(kw.value) for kw in call.keywords}
        receiver = self.eval(call.func.value) if isinstance(call.func, ast.Attribute) else None

        self.check_sinks(call, name, args, kwargs, receiver)

        # lista.append(x) / d.update(x): o contêiner passa a carregar o dado contaminado
        if isinstance(call.func, ast.Attribute) and call.func.attr in MUTATORS:
            incoming = union(*args, *kwargs.values())
            if incoming is not None:
                self.assign(call.func.value, union(receiver, incoming), line)

        if name in SOURCE_CALLS:
            return Taint(frozenset({SOURCE}), (TraceStep(line, f"fonte: {name}()", self.module.path),))
        if name in SANITIZERS or name.endswith(SANITIZER_SUFFIXES):
            return None

        callee, shift = self.engine.resolve(self.info, call)
        if callee is not None:
            return self._apply_summary(callee, shift, call, args, kwargs)

        result = union(receiver, *args, *kwargs.values())
        if result is not None and not isinstance(call.func, ast.Attribute):
            result = result.with_approx() if name not in EXACT_PROPAGATORS else result
        if result is not None and self._is_source_attr(name):
            return result
        if receiver is None and isinstance(call.func, ast.Attribute) and self._is_source_attr(self.module.qualname(call.func)):
            return Taint(frozenset({SOURCE}), (TraceStep(line, f"fonte: {ast.unparse(call.func)}()", self.module.path),))
        return result

    def _arg_for_param(self, callee: FunctionInfo, index: int, shift: int, args, kwargs) -> Taint | None:
        pos = index - shift
        if 0 <= pos < len(args):
            return args[pos]
        if index < len(callee.params):
            return kwargs.get(callee.params[index])
        return None

    def _apply_summary(self, callee: FunctionInfo, shift: int, call: ast.Call, args, kwargs) -> Taint | None:
        summary = callee.summary
        line = call.lineno
        # sinks alcançados dentro da função chamada
        for index, hits in summary.sink_params.items():
            taint = self._arg_for_param(callee, index, shift, args, kwargs)
            if taint is None:
                continue
            taint = taint.step(line, f"passado para {callee.name}() como '{callee.params[index]}'", self.module.path)
            for hit in hits:
                self._sink_hit(hit, taint)
        # retorno
        results = []
        for index in summary.returns_params:
            taint = self._arg_for_param(callee, index, shift, args, kwargs)
            if taint is not None:
                results.append(taint.step(line, f"propagado pelo retorno de {callee.name}()", self.module.path))
        if summary.returns_source is not None:
            results.append(summary.returns_source.step(line, f"retorno de {callee.name}() usado aqui", self.module.path))
        return union(*results)

    # --------------------------------------------------------------- sinks
    def check_sinks(self, call: ast.Call, name: str, args, kwargs, receiver) -> None:
        method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        hits: list[tuple[str, str, Taint | None]] = []
        sink = SINKS.get(name)
        if sink is not None:
            taint = args[sink.arg] if len(args) > sink.arg else kwargs.get(sink.kwarg) if sink.kwarg else None
            if sink.rule_id == "TAINT-DESER" and name.startswith("yaml.load"):
                loader = get_kwarg(call, "Loader")
                if loader is not None and self.module.qualname(loader).endswith("SafeLoader"):
                    taint = None
            hits.append((sink.rule_id, sink.label, taint))
        elif method in SQL_METHODS and args:
            hits.append(("TAINT-SQLI", f"{method}()", args[0]))
        elif name in SUBPROCESS and call.args:
            first = call.args[0]
            if is_true(get_kwarg(call, "shell")):
                hits.append(("TAINT-CMDI", f"{name}(shell=True)", args[0]))
            elif isinstance(first, (ast.List, ast.Tuple)) and first.elts:
                hits.append(("TAINT-CMDI", f"{name}() (programa executado)", self.eval(first.elts[0])))
        elif method in PATH_METHODS and receiver is not None:
            hits.append(("TAINT-PATH", f".{method}()", receiver))

        for rule_id, label, taint in hits:
            if taint is None:
                continue
            message = f"Dado não confiável alcança {label}."
            hit = SinkHit(rule_id, self.module, call.lineno, message, (TraceStep(call.lineno, f"sink: {label}", self.module.path),))
            self._sink_hit(hit, taint)

    def _check_html_return(self, stmt: ast.Return, taint: Taint) -> None:
        """Flask devolve strings como text/html: retornar HTML com entrada do usuário é XSS."""
        if self.info.route != "flask" or not taint.is_source:
            return
        constants = " ".join(n.value for n in ast.walk(stmt.value) if is_constant_str(n))
        if "<" in constants and ">" in constants:
            hit = SinkHit("TAINT-XSS", self.module, stmt.lineno,
                          "Entrada do usuário retornada dentro de HTML sem escape.",
                          (TraceStep(stmt.lineno, "sink: resposta HTML da rota", self.module.path),))
            self._sink_hit(hit, taint)

    def _sink_hit(self, hit: SinkHit, taint: Taint) -> None:
        if taint.is_source and self.report_mode:
            self.engine.report(hit, taint)
        for index in taint.params():
            # o parâmetro chega a um sink: vira parte do resumo da função
            entries = self.summary.sink_params.setdefault(index, [])
            relay = SinkHit(hit.rule_id, hit.module, hit.line, hit.message,
                            tuple(s for s in taint.trace if "parâmetro" not in s.description) + hit.trace)
            if not any(e.rule_id == relay.rule_id and e.line == relay.line and e.module is relay.module for e in entries):
                entries.append(relay)


def _exits(body: list[ast.stmt]) -> bool:
    """O bloco sempre termina com return/raise/continue/break/abort()?"""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        func = last.value.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        return name in {"abort", "exit", "_exit", "fail"}
    if isinstance(last, ast.If):
        return _exits(last.body) and _exits(last.orelse)
    return False
