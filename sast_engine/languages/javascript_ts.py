"""Analisador JavaScript/TypeScript baseado em Tree-sitter.

A linguagem alvo principal do projeto é Python; este módulo mostra que o motor é
multilinguagem: o Tree-sitter gera a árvore sintática concreta e as regras JS*
consultam os nós. Se o pacote não estiver instalado, a análise JS é ignorada.
"""
from __future__ import annotations

import re
from collections.abc import Iterator

from ..models import Confidence, Finding, Severity
from ..rules.catalog import CATALOG
from ..rules.secrets import is_secret_name, looks_like_secret_value, match_known_pattern

try:  # dependência opcional
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser

    _PARSER = Parser(Language(_tsjs.language()))
except Exception:  # pragma: no cover - ambiente sem tree-sitter
    _PARSER = None

SQL_RE = re.compile(r"\b(select\s.+\sfrom|insert\s+into|update\s.+\sset|delete\s+from)\b", re.I | re.S)


def available() -> bool:
    return _PARSER is not None


class _JSFile:
    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source.encode()
        self.lines = source.splitlines()
        self.tree = _PARSER.parse(self.source)

    def text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode(errors="replace")

    def finding(self, rule_id: str, node, message: str, severity: Severity | None = None,
                confidence: Confidence | None = None) -> Finding:
        meta = CATALOG[rule_id]
        line = node.start_point[0] + 1
        return Finding(
            rule_id=rule_id, title=meta.title, message=message, file=self.path, line=line,
            column=node.start_point[1], end_line=node.end_point[0] + 1,
            severity=severity or meta.severity, confidence=confidence or meta.confidence,
            cwe=meta.cwe, owasp=meta.owasp, snippet=self.lines[line - 1].rstrip() if line <= len(self.lines) else "",
            language="javascript", remediation=meta.remediation,
        )


def _walk(node) -> Iterator:
    cursor = node.walk()
    visited_children = False
    while True:
        if not visited_children:
            yield cursor.node
            if cursor.goto_first_child():
                continue
        if cursor.goto_next_sibling():
            visited_children = False
        elif cursor.goto_parent():
            visited_children = True
        else:
            return


def _string_value(js: _JSFile, node) -> str | None:
    if node is not None and node.type == "string":
        return js.text(node)[1:-1]
    if node is not None and node.type == "template_string" and not any(c.type == "template_substitution" for c in node.children):
        return js.text(node)[1:-1]
    return None


_NUMERIC_CASTS = ("parseInt(", "parseFloat(", "Number(", "Math.floor(", "Math.round(")


def _is_dynamic(node) -> bool:
    if node is None:
        return False
    if node.type == "template_string":
        subs = [c for c in node.children if c.type == "template_substitution"]
        # `${parseInt(id, 10)}` não permite injeção: só valores convertidos para número
        return any(not c.text.decode(errors="replace")[2:].lstrip().startswith(_NUMERIC_CASTS) for c in subs)
    if node.type == "binary_expression":
        return any(c.type not in {"string", "number", "+"} for c in node.children)
    return False


def scan_javascript(path: str, source: str) -> list[Finding]:
    if _PARSER is None:
        return []
    js = _JSFile(path, source)
    findings: list[Finding] = []
    for node in _walk(js.tree.root_node):
        t = node.type
        if t in {"call_expression", "new_expression"}:
            fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            args = node.child_by_field_name("arguments")
            name = js.text(fn) if fn is not None else ""
            first = args.named_children[0] if args is not None and args.named_children else None
            if name in {"eval", "window.eval", "Function"} or (t == "new_expression" and name == "Function"):
                sev = Severity.LOW if first is not None and first.type == "string" else None
                findings.append(js.finding("JS001", node, f"{name}() executa código dinamicamente.", severity=sev))
            elif name in {"setTimeout", "setInterval"} and first is not None and first.type in {"string", "template_string", "binary_expression"}:
                findings.append(js.finding("JS001", node, f"{name}() com string é equivalente a eval."))
            elif name in {"document.write", "document.writeln"} and first is not None and first.type != "string":
                findings.append(js.finding("JS002", node, f"{name}() com conteúdo dinâmico."))
            elif name.split(".")[-1] in {"exec", "execSync"} and first is not None and _is_dynamic(first):
                findings.append(js.finding("JS004", node, f"{name}() com comando montado dinamicamente."))
            elif name.split(".")[-1] in {"query", "execute", "raw"} and _is_dynamic(first):
                parts = js.text(first)
                if SQL_RE.search(parts):
                    findings.append(js.finding("JS005", node, "Consulta SQL montada com concatenação/template string."))
        elif t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "member_expression":
                prop = left.child_by_field_name("property")
                if prop is not None and js.text(prop) in {"innerHTML", "outerHTML"} and right is not None and right.type != "string":
                    findings.append(js.finding("JS002", node, f"Atribuição dinâmica a {js.text(prop)}."))
            if left is not None and right is not None:
                findings.extend(_secret(js, node, js.text(left), right))
        elif t == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and value is not None:
                findings.extend(_secret(js, node, js.text(name), value))
        elif t == "pair":
            key = node.child_by_field_name("key")
            value = node.child_by_field_name("value")
            if key is not None and value is not None:
                findings.extend(_secret(js, node, js.text(key).strip("'\""), value))
    return findings


def _secret(js: _JSFile, node, name: str, value_node) -> list[Finding]:
    value = _string_value(js, value_node)
    if value is None:
        return []
    label = match_known_pattern(value)
    if label:
        return [js.finding("JS003", node, f"{label} hardcoded em '{name}'.", Severity.CRITICAL, Confidence.HIGH)]
    if is_secret_name(name) and looks_like_secret_value(value):
        return [js.finding("JS003", node, f"Valor literal atribuído a '{name}', que parece ser uma credencial.")]
    return []


# =============================================================================================
# Taint analysis para JavaScript (Express / navegador) sobre a árvore do Tree-sitter.
# Escopo: intraprocedural e sensível à ordem das atribuições no arquivo. Reaproveita o modelo
# Taint (fonte, propagação, trace) da análise Python.
# =============================================================================================
from ..models import TraceStep  # noqa: E402
from ..taint import SOURCE, Taint, union  # noqa: E402

JS_SOURCE = re.compile(
    r"^(req|request|ctx\.request)\.(query|body|params|headers|cookies|url|originalUrl)\b"
    r"|^process\.argv\b|^(window\.)?location\.(search|hash|href)\b|^document\.(URL|cookie|referrer)\b"
)
JS_SANITIZERS = {
    "parseInt", "parseFloat", "Number", "Boolean", "encodeURIComponent", "escape", "escapeHtml",
    "DOMPurify.sanitize", "validator.escape", "validator.isInt", "path.basename", "he.encode",
    "xss", "sanitizeHtml", "mysql.escape", "connection.escape", "pg.escapeLiteral", "Math.floor",
}
JS_SINKS: dict[str, tuple[str, int]] = {}  # nome -> (regra, índice do argumento; -1 = último)
for _n in ("eval", "Function", "window.eval", "vm.runInNewContext", "vm.runInThisContext", "setTimeout", "setInterval"):
    JS_SINKS[_n] = ("TAINT-CODE", 0)
for _n in ("exec", "execSync", "child_process.exec", "child_process.execSync", "cp.exec", "cp.execSync"):
    JS_SINKS[_n] = ("TAINT-CMDI", 0)
for _n in ("res.send", "res.write", "res.end", "document.write", "document.writeln"):
    JS_SINKS[_n] = ("TAINT-XSS", 0)
for _n in ("fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs.writeFile", "fs.writeFileSync",
           "fs.unlink", "fs.unlinkSync", "fs.promises.readFile", "res.sendFile", "res.download"):
    JS_SINKS[_n] = ("TAINT-PATH", 0)
for _n in ("fetch", "axios", "axios.get", "axios.post", "axios.put", "axios.delete", "axios.request",
           "http.get", "https.get", "http.request", "https.request", "got", "request", "needle.get"):
    JS_SINKS[_n] = ("TAINT-SSRF", 0)
JS_SINKS["res.redirect"] = ("TAINT-REDIRECT", -1)
JS_SQL_METHODS = {"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe"}
_PASSTHROUGH = {"parenthesized_expression", "await_expression", "spread_element", "non_null_expression", "as_expression"}


class _JSTaint:
    def __init__(self, js: _JSFile):
        self.js = js
        self.state: dict[str, Taint] = {}
        self.findings: dict[tuple[str, int], Finding] = {}

    def step(self, node, desc: str) -> TraceStep:
        return TraceStep(node.start_point[0] + 1, desc, self.js.path)

    # ---------------------------------------------------------------- expressões
    def eval(self, node) -> Taint | None:
        if node is None:
            return None
        t = node.type
        if t in {"string", "number", "true", "false", "null", "undefined", "regex",
                 "arrow_function", "function_expression", "function", "class"}:
            return None
        if t == "identifier":
            return self.state.get(self.js.text(node))
        if t in {"member_expression", "subscript_expression"}:
            text = self.js.text(node)
            if JS_SOURCE.search(text):
                return Taint(frozenset({SOURCE}), (self.step(node, f"fonte: {text}"),))
            if text in self.state:
                return self.state[text]
            return self.eval(node.child_by_field_name("object"))
        if t == "template_string":
            return union(*(self.eval(c.named_children[0]) for c in node.named_children
                           if c.type == "template_substitution" and c.named_children))
        if t == "binary_expression":
            if node.child_by_field_name("operator") is not None and self.js.text(node.child_by_field_name("operator")) != "+":
                return None  # comparação/aritmética não carrega o texto
            return union(self.eval(node.child_by_field_name("left")), self.eval(node.child_by_field_name("right")))
        if t == "ternary_expression":
            return union(self.eval(node.child_by_field_name("consequence")), self.eval(node.child_by_field_name("alternative")))
        if t in {"array", "object", "pair", "arguments"}:
            return union(*(self.eval(c.child_by_field_name("value") if c.type == "pair" else c) for c in node.named_children))
        if t in _PASSTHROUGH and node.named_children:
            return self.eval(node.named_children[0])
        if t in {"call_expression", "new_expression"}:
            return self.eval_call(node)
        if t == "assignment_expression":
            return self.eval(node.child_by_field_name("right"))
        return None

    def eval_call(self, node) -> Taint | None:
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        name = self.js.text(fn) if fn is not None else ""
        args_node = node.child_by_field_name("arguments")
        arg_nodes = args_node.named_children if args_node is not None else []
        args = [self.eval(a) for a in arg_nodes]
        self.check_sink(node, name, arg_nodes, args)
        if name in JS_SANITIZERS or name.rsplit(".", 1)[-1] in {"escape", "sanitize", "isInt", "isNumeric"}:
            return None
        receiver = self.eval(fn.child_by_field_name("object")) if fn is not None and fn.type == "member_expression" else None
        if fn is not None and fn.type == "member_expression" and JS_SOURCE.search(self.js.text(fn)) and receiver is None:
            receiver = Taint(frozenset({SOURCE}), (self.step(node, f"fonte: {name}()"),))
        return union(receiver, *args)

    # --------------------------------------------------------------------- sinks
    def check_sink(self, node, name: str, arg_nodes, args) -> None:
        rule, label, taint = None, name, None
        simple = name.rsplit(".", 1)[-1]
        if name in JS_SINKS or simple in {"exec", "execSync"}:
            rule, index = JS_SINKS.get(name, ("TAINT-CMDI", 0))
            if args:
                taint = args[index] if -len(args) <= index < len(args) else None
            if rule == "TAINT-CODE" and simple in {"setTimeout", "setInterval"} and arg_nodes and arg_nodes[0].type in {"arrow_function", "function_expression", "identifier"}:
                taint = None  # callback, não string
        elif simple in JS_SQL_METHODS and args:
            rule, label, taint = "TAINT-SQLI", f"{simple}()", args[0]
        elif simple == "insertAdjacentHTML" and len(args) > 1:
            rule, label, taint = "TAINT-XSS", "insertAdjacentHTML()", args[1]
        if rule and taint is not None and taint.is_source:
            self.report(rule, node, label, taint)

    def report(self, rule_id: str, node, label: str, taint: Taint) -> None:
        line = node.start_point[0] + 1
        if (rule_id, line) in self.findings:
            return
        meta = CATALOG[rule_id]
        finding = self.js.finding(rule_id, node, f"Dado não confiável alcança {label}.")
        finding.engine = "sast-engine/taint"
        finding.trace = list(taint.trace) + [self.step(node, f"sink: {label}")]
        finding.severity, finding.confidence = meta.severity, Confidence.HIGH
        self.findings[(rule_id, line)] = finding

    # ---------------------------------------------------------------- atribuições
    def assign(self, name: str, taint: Taint | None, node) -> None:
        if taint is None:
            self.state.pop(name, None)
        else:
            self.state[name] = Taint(taint.origins, taint.trace + (self.step(node, f"atribuído a '{name}'"),), taint.approx)

    def run(self) -> list[Finding]:
        for node in _walk(self.js.tree.root_node):
            t = node.type
            if t == "variable_declarator":
                name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
                if name is not None and value is not None:
                    taint = self.eval(value)
                    if name.type == "identifier":
                        self.assign(self.js.text(name), taint, node)
                    else:  # desestruturação: const { host } = req.query
                        for ident in _walk(name):
                            if ident.type in {"identifier", "shorthand_property_identifier_pattern"}:
                                self.assign(self.js.text(ident), taint, node)
            elif t == "assignment_expression":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                taint = self.eval(right)
                if left is not None and left.type == "member_expression":
                    prop = left.child_by_field_name("property")
                    if prop is not None and self.js.text(prop) in {"innerHTML", "outerHTML"} and taint is not None and taint.is_source:
                        self.report("TAINT-XSS", node, self.js.text(prop), taint)
                if left is not None:
                    self.assign(self.js.text(left), taint, node)
            elif t in {"call_expression", "new_expression"}:
                self.eval_call(node)
        return list(self.findings.values())


def taint_javascript(path: str, source: str) -> list[Finding]:
    if _PARSER is None:
        return []
    return _JSTaint(_JSFile(path, source)).run()
