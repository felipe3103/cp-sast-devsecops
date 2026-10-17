"""Parser Python baseado no módulo `ast` da biblioteca padrão.

Constrói a Árvore de Sintaxe Abstrata e um contexto com tudo o que as regras
precisam: mapa de imports (para resolver aliases como `import subprocess as sp`),
mapa de nós pais e acesso às linhas do código-fonte.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class PythonModule:
    path: str
    source: str
    tree: ast.Module
    lines: list[str] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)
    parents: dict[int, ast.AST] = field(default_factory=dict)

    def snippet(self, line: int, end_line: int | None = None) -> str:
        end = end_line or line
        end = min(end, line + 4)  # trechos curtos no relatório
        return "\n".join(self.lines[line - 1 : end]).rstrip()

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def parent(self, node: ast.AST) -> ast.AST | None:
        return self.parents.get(id(node))

    # ------------------------------------------------------------------ nomes
    def qualname(self, node: ast.AST) -> str:
        """Nome qualificado de uma expressão, resolvendo aliases de import.

        `sp.Popen` com `import subprocess as sp` -> `subprocess.Popen`
        `loads` com `from pickle import loads` -> `pickle.loads`
        `cursor.execute` (variável local) -> `cursor.execute`
        """
        parts: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(self.imports.get(current.id, current.id))
        elif isinstance(current, ast.Call):
            parts.append(self.qualname(current.func) + "()")
        else:
            return ""
        return ".".join(reversed(parts))

    def call_name(self, call: ast.Call) -> str:
        return self.qualname(call.func)


def parse_python(path: str, source: str) -> PythonModule:
    tree = ast.parse(source, filename=path, type_comments=False)
    module = PythonModule(path=path, source=source, tree=tree, lines=source.splitlines())
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            module.parents[id(child)] = parent
        if isinstance(parent, ast.Import):
            for alias in parent.names:
                local = alias.asname or alias.name.split(".")[0]
                module.imports[local] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(parent, ast.ImportFrom) and parent.module and parent.level == 0:
            for alias in parent.names:
                module.imports[alias.asname or alias.name] = f"{parent.module}.{alias.name}"
    return module


# ---------------------------------------------------------------- utilitários
def get_kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def is_constant_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_literal(node: ast.AST | None) -> bool:
    """Expressão composta somente de constantes (não depende de dados externos)."""
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(is_literal(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(is_literal(k) for k in node.keys if k) and all(is_literal(v) for v in node.values)
    if isinstance(node, ast.BinOp):
        return is_literal(node.left) and is_literal(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def is_dynamic_string(node: ast.AST | None) -> bool:
    """String montada dinamicamente: f-string, concatenação, % ou .format()."""
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not is_literal(node)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and (node.args or node.keywords)
    ):
        return True
    return False


def target_names(target: ast.AST) -> list[str]:
    """Nomes atribuídos por um alvo de atribuição (suporta tuplas e atributos)."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in target.elts:
            out.extend(target_names(elt))
        return out
    if isinstance(target, ast.Starred):
        return target_names(target.value)
    if isinstance(target, ast.Attribute):
        return [ast.unparse(target)]
    return []
