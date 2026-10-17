"""Infraestrutura do registro de regras.

Cada regra Python declara os tipos de nó AST que inspeciona. O motor percorre a
árvore UMA única vez e despacha cada nó apenas para as regras interessadas,
o que mantém a análise linear no tamanho do código.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Callable, Iterator

from ..languages.python_ast import PythonModule
from ..models import Confidence, Finding, Severity
from .catalog import CATALOG

CheckFn = Callable[[ast.AST, PythonModule], Iterator[Finding]]

_PY_RULES: dict[type, list[tuple[str, CheckFn]]] = defaultdict(list)


def python_rule(rule_id: str, *node_types: type) -> Callable[[CheckFn], CheckFn]:
    if rule_id not in CATALOG:
        raise KeyError(f"Regra {rule_id} não está no catálogo")

    def decorator(fn: CheckFn) -> CheckFn:
        for node_type in node_types:
            _PY_RULES[node_type].append((rule_id, fn))
        return fn

    return decorator


def python_rules_for(node: ast.AST) -> list[tuple[str, CheckFn]]:
    return _PY_RULES.get(type(node), [])


def registered_python_rules() -> set[str]:
    return {rid for checks in _PY_RULES.values() for rid, _ in checks}


def make_finding(
    rule_id: str,
    module: PythonModule,
    node: ast.AST,
    message: str,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    **extra,
) -> Finding:
    meta = CATALOG[rule_id]
    line = getattr(node, "lineno", 1)
    end_line = getattr(node, "end_lineno", line)
    return Finding(
        rule_id=rule_id,
        title=meta.title,
        message=message,
        file=module.path,
        line=line,
        column=getattr(node, "col_offset", 0),
        end_line=end_line,
        severity=severity if severity is not None else meta.severity,
        confidence=confidence if confidence is not None else meta.confidence,
        cwe=meta.cwe,
        owasp=meta.owasp,
        snippet=module.snippet(line, end_line),
        remediation=meta.remediation,
        extra=extra,
    )
