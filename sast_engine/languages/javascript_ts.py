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


def _is_dynamic(node) -> bool:
    if node is None:
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.children)
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
