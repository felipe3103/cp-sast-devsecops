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
from .ollama_client import LLMUnavailable, OllamaClient
from .prompts import (
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


def apply_fix(source: str, line: int, fixed_code: str) -> tuple[str, int, int] | None:
    """Aplica a correção no arquivo real: substitui a função inteira (se o LLM devolveu a
    função) ou a instrução da linha do achado. Retorna (código novo, linha inicial, linha final)."""
    try:
        tree = ast.parse(source)
        fixed_tree = ast.parse(fixed_code)
    except SyntaxError:
        return None
    lines = source.splitlines()
    func = _innermost(tree, line, (ast.FunctionDef, ast.AsyncFunctionDef))
    fixed_defs = [n for n in fixed_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if func is not None and any(d.name == func.name for d in fixed_defs):
        has_decorators = any(d.decorator_list for d in fixed_defs if d.name == func.name)
        first = func.decorator_list[0].lineno if (func.decorator_list and has_decorators) else func.lineno
        target_start, target_end, indent = first, func.end_lineno, func.col_offset
    else:
        stmt = _innermost(tree, line, (ast.stmt,))
        if stmt is None:
            return None
        target_start, target_end, indent = stmt.lineno, stmt.end_lineno, stmt.col_offset
    replacement = [(" " * indent + l) if l.strip() else l for l in fixed_code.splitlines()]
    patched = lines[: target_start - 1] + replacement + lines[target_end:]
    return "\n".join(patched) + "\n", target_start, target_start + len(replacement) - 1


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
        self.client = client or OllamaClient()
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
        prompt = TRIAGE_USER.format(
            rule_id=finding.rule_id, title=finding.title, cwe=finding.cwe, owasp=finding.owasp,
            severity=finding.severity.name, confidence=finding.confidence.name, message=finding.message,
            file=finding.file, line=finding.line, trace=trace,
            description=meta.description if meta else "", language=finding.language, context=context,
        )
        self._current_source = enclosing_function(source, finding.line) or finding.snippet
        self._ctx = (source if source and source != finding.snippet else None, project_files)
        try:
            raw = self.client.chat_json(TRIAGE_SYSTEM, prompt, TRIAGE_SCHEMA)
            analysis = self._apply_guardrails(finding, raw)
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
    def semantic_review(self, path: str, source: str, language: str = "python") -> list[Finding]:
        """Pede ao LLM falhas de lógica (IDOR, autorização ausente...) que regras não capturam."""
        numbered = "\n".join(f"{i:4} | {l}" for i, l in enumerate(source.splitlines(), 1))
        try:
            raw = self.client.chat_json(SEMANTIC_SYSTEM, SEMANTIC_USER.format(file=path, language=language, code=numbered), SEMANTIC_SCHEMA)
        except LLMUnavailable:
            return []
        lines = source.splitlines()
        findings = []
        for issue in raw.get("issues", []):
            try:
                line = int(issue["line"])
                conf = float(issue.get("confidence", 0))
                severity = Severity.parse(issue["severity"])
            except (KeyError, ValueError, TypeError):
                continue
            if not 1 <= line <= len(lines) or conf < 0.6:
                continue  # descarta linhas inexistentes (alucinação) e baixa confiança
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

