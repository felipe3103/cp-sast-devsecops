"""Triagem semântica com LLM local: classificação, redução de falsos positivos e remediação.

Guardrails aplicados sobre a resposta do modelo:
1. Saída estruturada (JSON schema) validada; resposta inválida -> base de conhecimento.
2. A IA ajusta a severidade em no máximo 1 nível (evita alucinação de criticidade).
3. A IA não suprime sozinha um fluxo de taint comprovado com alta confiança: o achado vai
   para revisão humana ("needs_review") em vez de ser descartado.
4. A correção sugerida é validada em ciclo fechado: precisa compilar e, re-escaneada pelo
   próprio motor, não pode mais disparar a mesma regra.
"""
from __future__ import annotations

import ast
import hashlib
import textwrap
from dataclasses import asdict, dataclass, field

from ..languages.python_ast import parse_python
from ..models import Confidence, Finding, Severity
from ..rules.catalog import CATALOG
from .ollama_client import LLMUnavailable, OllamaClient, default_client
from .prompts import (
    FUNCTION_SCHEMA,
    FUNCTION_SYSTEM,
    FUNCTION_USER,
    FIX_RETRY_SCHEMA,
    FIX_RETRY_USER,
    SEMANTIC_SCHEMA,
    SEMANTIC_SYSTEM,
    SEMANTIC_USER,
    TRIAGE_SCHEMA,
    TRIAGE_SYSTEM,
    TRIAGE_USER,
)

FP_SUPPRESS_THRESHOLD = 0.8
CONTEXT_LINES = 12
MAX_FIX_RETRIES = 2  # novas tentativas guiadas pelo erro do validador


@dataclass
class AIAnalysis:
    verdict: str                      # true_positive | false_positive | uncertain | needs_review
    confidence: float
    severity: str
    original_severity: str
    justification: str
    remediation: str
    fixed_code: str = ""
    exploit_scenario: str = ""
    fix_validated: bool | None = None  # None = não foi possível validar
    fix_validation_note: str = ""
    suppressed: bool = False
    source: str = "llm"                # llm | knowledge_base
    model: str = ""
    notes: list[str] = field(default_factory=list)
    rag_documents: list[str] = field(default_factory=list)  # ids da base usados no prompt (RAG)

    def to_dict(self) -> dict:
        return asdict(self)


def code_context(source: str, line: int, radius: int = CONTEXT_LINES) -> str:
    lines = source.splitlines()
    start, end = max(1, line - radius), min(len(lines), line + radius)
    width = len(str(end))
    return "\n".join(
        f"{'>>' if n == line else '  '} {str(n).rjust(width)} | {lines[n - 1]}" for n in range(start, end + 1)
    )


def _clean_code(code) -> str:
    code = str(code or "").strip()
    if code.startswith("```"):
        code = "\n".join(l for l in code.splitlines() if not l.startswith("```"))
    return code


def enclosing_function(source: str, line: int) -> str:
    """Código da função que contém a linha (contexto mínimo para o LLM reescrever)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or node.lineno):
            if best is None or node.lineno > best.lineno:
                best = node
    if best is None:
        return ""
    start = best.decorator_list[0].lineno if best.decorator_list else best.lineno
    return "\n".join(source.splitlines()[start - 1 : best.end_lineno])


def knowledge_base_analysis(finding: Finding, note: str = "") -> AIAnalysis:
    """Fallback determinístico quando o LLM não está disponível."""
    meta = CATALOG.get(finding.rule_id)
    return AIAnalysis(
        verdict="uncertain",
        confidence=0.0,
        severity=finding.severity.name,
        original_severity=finding.severity.name,
        justification=(meta.description if meta else finding.message),
        remediation=(meta.remediation if meta else finding.remediation or "Revisar manualmente."),
        fixed_code=(meta.fix_example if meta else ""),
        source="knowledge_base",
        notes=[note] if note else [],
    )


def _innermost(tree: ast.AST, line: int, types: tuple) -> ast.AST | None:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, types) and node.lineno <= line <= (node.end_lineno or node.lineno):
            if best is None or (node.lineno, -(node.end_lineno or 0)) > (best.lineno, -(best.end_lineno or 0)):
                best = node
    return best


def _target_region(tree: ast.AST, line: int, fixed_tree: ast.AST) -> tuple[ast.AST, int, int, int] | None:
    """Trecho do arquivo que a correção substitui: a função inteira (se o LLM devolveu a
    função) ou a instrução da linha do achado. Retorna (nó original, início, fim, indentação)."""
    func = _innermost(tree, line, (ast.FunctionDef, ast.AsyncFunctionDef))
    fixed_defs = [n for n in fixed_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if func is not None and any(d.name == func.name for d in fixed_defs):
        has_decorators = any(d.decorator_list for d in fixed_defs if d.name == func.name)
        first = func.decorator_list[0].lineno if (func.decorator_list and has_decorators) else func.lineno
        return func, first, func.end_lineno, func.col_offset
    stmt = _innermost(tree, line, (ast.stmt,))
    if stmt is None:
        return None
    return stmt, stmt.lineno, stmt.end_lineno, stmt.col_offset


def apply_fix(source: str, line: int, fixed_code: str) -> tuple[str, int, int] | None:
    """Aplica a correção no arquivo real. Retorna (código novo, linha inicial, linha final)."""
    try:
        tree = ast.parse(source)
        fixed_tree = ast.parse(fixed_code)
    except SyntaxError:
        return None
    region = _target_region(tree, line, fixed_tree)
    if region is None:
        return None
    _, target_start, target_end, indent = region
    lines = source.splitlines()
    replacement = [(" " * indent + l) if l.strip() else l for l in fixed_code.splitlines()]
    patched = lines[: target_start - 1] + replacement + lines[target_end:]
    return "\n".join(patched) + "\n", target_start, target_start + len(replacement) - 1


def _assigned_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                names |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if item.optional_vars is not None:
                    names |= {x.id for x in ast.walk(item.optional_vars) if isinstance(x, ast.Name)}
    return names


def preserves_behavior(source: str, line: int, fixed_code: str) -> tuple[bool, str]:
    """Uma correção não pode "eliminar" a falha apagando a funcionalidade.

    Exige que o trecho corrigido ainda defina as mesmas variáveis, ainda faça uma chamada
    (a operação original, ou uma equivalente segura) e ainda retorne um valor, se o original
    retornava. Ex.: trocar `rows = conn.execute(q).fetchall()` por `query = f` é rejeitado.
    """
    try:
        tree, fixed_tree = ast.parse(source), ast.parse(fixed_code)
    except SyntaxError:
        return True, ""  # a compilação é checada em outro passo
    region = _target_region(tree, line, fixed_tree)
    if region is None:
        return True, ""
    original = region[0]
    # numa instrução, as variáveis definidas precisam continuar definidas; numa função
    # reescrita inteira, variáveis intermediárias podem sumir legitimamente
    is_function = isinstance(original, (ast.FunctionDef, ast.AsyncFunctionDef))
    missing = set() if is_function else _assigned_names(original) - _assigned_names(fixed_tree)
    if missing:
        return False, f"a correção remove a operação original ('{sorted(missing)[0]}' deixa de ser definido)"

    def has_call(node: ast.AST) -> bool:
        return any(isinstance(n, ast.Call) for n in ast.walk(node))

    if has_call(original) and not has_call(fixed_tree):
        return False, "a correção remove a chamada original em vez de torná-la segura"

    def returns_value(node: ast.AST) -> bool:
        return any(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(node))

    if returns_value(original) and not returns_value(fixed_tree):
        return False, "a correção remove o valor de retorno do código original"
    return True, ""


def validate_fix(
    finding: Finding,
    fixed_code: str,
    source: str | None = None,
    project_files: dict[str, str] | None = None,
) -> tuple[bool | None, str]:
    """Validação em ciclo fechado da correção sugerida pela IA.

    Com o código-fonte disponível, a correção é APLICADA no arquivo real e o projeto inteiro é
    re-escaneado: assim a taint analysis interprocedural (fonte em outro arquivo) também é
    verificada. A correção é rejeitada se não compilar, se a vulnerabilidade continuar ou se
    introduzir um achado novo na região alterada.
    """
    from ..scanner import ScanConfig, scan_sources  # import tardio evita ciclo

    if finding.language != "python" or not fixed_code.strip():
        return None, "validação automática disponível apenas para Python"
    code = textwrap.dedent(fixed_code).strip("\n")
    try:
        parse_python("fix.py", code)
    except SyntaxError as exc:
        return False, f"correção não compila: {exc.msg} (linha {exc.lineno})"

    def same_vuln(f: Finding) -> bool:
        return f.rule_id == finding.rule_id or bool(f.cwe and f.cwe == finding.cwe)

    if not source:
        result = scan_sources({"fix.py": code}, ScanConfig())
        remaining = [f for f in result.findings if same_vuln(f)]
        if remaining:
            return False, f"a correção ainda dispara {remaining[0].rule_id}: {remaining[0].message}"
        return True, "correção compila e não dispara mais a regra (validada isoladamente)"

    keeps, why = preserves_behavior(source, finding.line, code)
    if not keeps:
        return False, why
    applied = apply_fix(source, finding.line, code)
    if applied is None:
        return None, "não foi possível aplicar a correção no arquivo"
    patched, start, end = applied
    try:
        parse_python(finding.file, patched)
    except SyntaxError as exc:
        return False, f"arquivo corrigido não compila: {exc.msg} (linha {exc.lineno})"

    files = dict(project_files or {})
    before = scan_sources({**files, finding.file: source}, ScanConfig()).findings
    after = scan_sources({**files, finding.file: patched}, ScanConfig()).findings
    in_region = [f for f in after if f.file == finding.file and start <= f.line <= end]
    remaining = [f for f in in_region if same_vuln(f)]
    if remaining:
        return False, f"aplicada ao arquivo, a correção ainda dispara {remaining[0].rule_id} na linha {remaining[0].line}: {remaining[0].message}"
    known = {(f.rule_id, " ".join(f.snippet.split())) for f in before}
    introduced = [f for f in in_region if (f.rule_id, " ".join(f.snippet.split())) not in known and f.severity >= Severity.MEDIUM]
    if introduced:
        return False, f"a correção introduz {introduced[0].rule_id}: {introduced[0].message}"
    scope = f"{len(files) + (finding.file not in files)} arquivo(s)"
    return True, f"correção aplicada no arquivo e projeto re-escaneado ({scope}): vulnerabilidade eliminada"


class AITriage:
    def __init__(self, client: OllamaClient | None = None, cache: dict | None = None):
        self.client = client or default_client()
        self.use_rag = client is None or getattr(client, "use_rag", False)
        self.cache = cache if cache is not None else {}

    def _cache_key(self, finding: Finding, context: str) -> str:
        raw = f"{self.client.model}|{finding.rule_id}|{context}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def analyze(self, finding: Finding, source: str, project_files: dict[str, str] | None = None) -> AIAnalysis:
        """Triagem de um achado. `project_files` permite validar a correção no projeto inteiro."""
        context = code_context(source, finding.line)
        key = self._cache_key(finding, context)
        self._ctx = (None, None)
        if key in self.cache:
            return AIAnalysis(**self.cache[key])

        meta = CATALOG.get(finding.rule_id)
        trace = ""
        if finding.trace:
            trace = "- Fluxo de dados detectado (taint):\n" + "\n".join(
                f"    linha {s.line}: {s.description}" for s in finding.trace
            )
        rag_text, rag_ids = ("", [])
        if self.use_rag:
            from .rag import rag_context

            rag_text, rag_ids = rag_context(finding, getattr(self.client, "base_url", None))
        prompt = TRIAGE_USER.format(
            rule_id=finding.rule_id, title=finding.title, cwe=finding.cwe, owasp=finding.owasp,
            severity=finding.severity.name, confidence=finding.confidence.name, message=finding.message,
            file=finding.file, line=finding.line, trace=trace,
            description=meta.description if meta else "", language=finding.language, context=context,
        ) + (f"\n\n{rag_text}" if rag_text else "")
        self._current_source = enclosing_function(source, finding.line) or finding.snippet
        self._ctx = (source if source and source != finding.snippet else None, project_files)
        try:
            raw = self.client.chat_json(TRIAGE_SYSTEM, prompt, TRIAGE_SCHEMA)
            analysis = self._apply_guardrails(finding, raw)
            analysis.rag_documents = rag_ids
        except (LLMUnavailable, KeyError, ValueError, TypeError) as exc:
            return knowledge_base_analysis(finding, f"LLM indisponível ou resposta inválida: {exc}")

        self.cache[key] = analysis.to_dict()
        return analysis

    def _function_source(self, finding: Finding) -> str:
        return getattr(self, "_current_source", "") or finding.snippet

    def _apply_guardrails(self, finding: Finding, raw: dict) -> AIAnalysis:
        verdict = raw["verdict"] if raw.get("verdict") in {"true_positive", "false_positive", "uncertain"} else "uncertain"
        confidence = max(0.0, min(1.0, float(raw.get("confidence", 0))))
        notes: list[str] = []

        original = finding.severity
        try:
            proposed = Severity.parse(raw.get("severity", original.name))
        except KeyError:
            proposed = original
        if abs(int(proposed) - int(original)) > 1:
            bounded = Severity(int(original) + (1 if proposed > original else -1))
            notes.append(f"IA sugeriu {proposed.name}; limitado a {bounded.name} (máx. 1 nível de ajuste)")
            proposed = bounded

        suppressed = False
        if verdict == "false_positive":
            proven_flow = finding.rule_id.startswith("TAINT-") and finding.confidence == Confidence.HIGH
            if proven_flow:
                verdict = "needs_review"
                notes.append("IA apontou falso positivo em fluxo de taint comprovado: enviado para revisão humana")
            elif confidence >= FP_SUPPRESS_THRESHOLD:
                suppressed = True
            else:
                verdict = "needs_review"
                notes.append(f"confiança {confidence:.2f} abaixo do limiar {FP_SUPPRESS_THRESHOLD} para suprimir")

        fixed_code = _clean_code(raw.get("fixed_code", ""))
        valid, note = validate_fix(finding, fixed_code, *self._ctx) if verdict != "false_positive" else (None, "")
        # Ciclo de autocorreção: o erro do validador volta para o LLM, que tenta de novo.
        for attempt in range(MAX_FIX_RETRIES):
            if valid is not False:
                break
            meta = CATALOG.get(finding.rule_id)
            try:
                retry = self.client.chat_json(TRIAGE_SYSTEM, FIX_RETRY_USER.format(
                    error=note, language=finding.language, snippet=self._function_source(finding),
                    rule_id=finding.rule_id, title=finding.title, cwe=finding.cwe,
                    remediation=meta.remediation if meta else finding.remediation,
                ), FIX_RETRY_SCHEMA)
            except LLMUnavailable:
                break
            candidate = _clean_code(retry.get("fixed_code", ""))
            ok, retry_note = validate_fix(finding, candidate, *self._ctx)
            notes.append(f"tentativa {attempt + 2} de correção: {retry_note}")
            if ok:
                fixed_code, valid, note = candidate, ok, f"{retry_note} (após autocorreção)"

        return AIAnalysis(
            verdict=verdict,
            confidence=confidence,
            severity=proposed.name,
            original_severity=original.name,
            justification=str(raw.get("justification", "")),
            exploit_scenario=str(raw.get("exploit_scenario", "")),
            remediation=str(raw.get("remediation", "")),
            fixed_code=fixed_code,
            fix_validated=valid,
            fix_validation_note=note,
            suppressed=suppressed,
            model=self.client.model,
            notes=notes,
        )

    # --------------------------------------------------- varredura semântica
    def semantic_review(
        self, path: str, source: str, language: str = "python", known: list[Finding] | None = None,
    ) -> list[Finding]:
        """Pede ao LLM falhas de LÓGICA (IDOR, autorização ausente...) que regras não capturam.

        - Comentários são removidos antes do envio: o modelo julga só o código (e não pode
          "colar" de anotações como as do benchmark).
        - Os achados que o motor já tem são informados ao modelo e, se ele repetir algum
          mesmo assim, o achado é descartado (mesmo arquivo, até 2 linhas de distância).
        """
        known = [f for f in (known or []) if f.file == path]
        if language == "python":
            per_function = self._semantic_by_function(path, source, known)
            if per_function is not None:
                return per_function
        code = strip_comments(source, language)
        numbered = "\n".join(f"{i:4} | {l}" for i, l in enumerate(code.splitlines(), 1))
        already = "\n".join(f"- linha {f.line}: {f.rule_id} {f.title}" for f in known) or "- nenhum"
        try:
            raw = self.client.chat_json(
                SEMANTIC_SYSTEM,
                SEMANTIC_USER.format(file=path, language=language, code=numbered, known=already),
                SEMANTIC_SCHEMA,
            )
        except LLMUnavailable:
            return []
        lines = source.splitlines()
        findings: list[Finding] = []
        for issue in raw.get("issues", []):
            try:
                line = int(issue["line"])
                conf = float(issue.get("confidence", 0))
                severity = Severity.parse(issue["severity"])
            except (KeyError, ValueError, TypeError):
                continue
            if not 1 <= line <= len(lines) or not lines[line - 1].strip() or conf < 0.6:
                continue  # linha inexistente/vazia (alucinação) ou baixa confiança
            if any(abs(f.line - line) <= 2 for f in known + findings):
                continue  # repetição de achado já conhecido
            findings.append(Finding(
                rule_id="AI-SEMANTIC",
                title=str(issue.get("title", "Falha lógica"))[:120],
                message=str(issue.get("explanation", "")),
                file=path, line=line, severity=min(severity, Severity.HIGH),
                confidence=Confidence.MEDIUM if conf >= 0.8 else Confidence.LOW,
                cwe=str(issue.get("cwe", "")), owasp="", snippet=lines[line - 1].strip(),
                engine=f"ai/{self.client.model}", language=language,
                remediation=str(issue.get("remediation", "")),
            ))
        return findings

    def _semantic_by_function(self, path: str, source: str, known: list[Finding]) -> list[Finding] | None:
        """Para cada função de rota (achada pela AST), o LLM responde perguntas objetivas e o
        código converte as respostas em achados com CWE. Retorna None se não houver rotas."""
        from ..taint import ROUTE_DECORATORS

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        routes = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
                        routes.append(node)
                        break
        if not routes:
            return None
        lines = source.splitlines()
        findings: list[Finding] = []
        for fn in routes:
            start = fn.decorator_list[0].lineno if fn.decorator_list else fn.lineno
            code = strip_comments("\n".join(lines[start - 1 : fn.end_lineno]))
            try:
                ans = self.client.chat_json(FUNCTION_SYSTEM, FUNCTION_USER.format(file=path, language="python", code=code), FUNCTION_SCHEMA)
            except LLMUnavailable:
                return findings
            if not isinstance(ans, dict):
                continue
            why = str(ans.get("explanation", ""))
            # Checagem cruzada: "altera dados" só vale com evidência na AST (o LLM às vezes afirma
            # isso de funções que só leem, como um GET que abre um arquivo).
            if ans.get("modifies_data") and not _mutates(fn):
                ans["modifies_data"] = False
            issues = []
            if ans.get("accesses_resource_by_id") and not ans.get("checks_resource_owner"):
                issues.append(("CWE-639", "Acesso a recurso de outro usuário (IDOR)", Severity.HIGH,
                               f"{fn.name}() acessa um registro pelo id recebido sem conferir se ele pertence ao usuário logado.",
                               "Filtrar pelo dono: buscar o registro com o id E o usuário da sessão, ou retornar 403."))
            if ans.get("modifies_data") and not ans.get("requires_authentication"):
                issues.append(("CWE-306", "Operação sensível sem autenticação", Severity.HIGH,
                               f"{fn.name}() altera dados sem verificar se há um usuário autenticado.",
                               "Exigir login (decorator ou checagem da sessão) antes de alterar dados."))
            if ans.get("trusts_client_sensitive_value"):
                value = str(ans.get("sensitive_value", "")).strip()
                issues.append(("CWE-602", "Valor sensível controlado pelo cliente", Severity.MEDIUM,
                               f"{fn.name}() confia em um valor enviado pelo cliente{f' ({value})' if value else ''} que deveria ser decidido no servidor.",
                               "Calcular o valor no servidor (preço, desconto, papel, usuário da sessão); nunca aceitá-lo do cliente."))
            for cwe, title, severity, message, fix in issues:
                if any(f.cwe == cwe and f.file == path and fn.lineno <= f.line <= fn.end_lineno for f in known):
                    continue
                findings.append(Finding(
                    rule_id="AI-SEMANTIC", title=title, message=f"{message} {why}".strip(), file=path,
                    line=fn.lineno, end_line=fn.end_lineno, severity=severity, confidence=Confidence.LOW,
                    cwe=cwe, owasp="A01:2021 - Broken Access Control" if cwe != "CWE-602" else "A04:2021 - Insecure Design",
                    snippet=lines[fn.lineno - 1].strip(), engine=f"ai/{self.client.model}", language="python",
                    remediation=fix,
                ))
        return findings


MUTATING_METHODS = {"post", "put", "patch", "delete"}
MUTATING_CALL = ("save", "salvar", "delete", "apagar", "remove", "remover", "update", "atualizar",
                 "commit", "cancel", "cancelar", "insert", "inserir", "destroy", "excluir")


def _mutates(fn: ast.AST) -> bool:
    """Evidência sintática de que a rota altera estado."""
    for dec in getattr(fn, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in MUTATING_METHODS:
            return True
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "methods" and any(
                    isinstance(e, ast.Constant) and str(e.value).lower() in MUTATING_METHODS
                    for e in ast.walk(kw.value)
                ):
                    return True
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name.lower().startswith(MUTATING_CALL):
                return True
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, (ast.Attribute, ast.Subscript)) for t in targets):
                return True
    return False


def strip_comments(source: str, language: str = "python") -> str:
    """Remove comentários preservando a numeração das linhas."""
    if language == "python":
        import io
        import tokenize

        lines = source.splitlines()
        try:
            for tok in tokenize.generate_tokens(io.StringIO(source).readline):
                if tok.type == tokenize.COMMENT:
                    row, col = tok.start
                    lines[row - 1] = lines[row - 1][:col].rstrip()
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return source
        return "\n".join(lines)
    import re

    return "\n".join(re.sub(r"\s*//(?![^'\"`]*['\"`]).*$", "", l) for l in source.splitlines())
