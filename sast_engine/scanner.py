"""Orquestrador da varredura SAST."""
from __future__ import annotations

import ast
import fnmatch
import os
import re
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import integrations
from .languages import javascript_ts
from .languages.python_ast import PythonModule, parse_python
from .models import Finding, ParseError, ScanResult, Severity
from .rules import python_rules  # noqa: F401  (registra as regras)
from .rules.base import python_rules_for
from .taint import TaintEngine

DEFAULT_EXCLUDES = [
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__", "dist", "build", ".tox",
    ".mypy_cache", ".pytest_cache", "site-packages", "*.min.js",
]
LANG_BY_EXT = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript"}
MAX_FILE_BYTES = 1_000_000

SUPPRESS_RE = re.compile(r"#\s*nosast(?::\s*([\w\-, ]+))?|//\s*nosast(?::\s*([\w\-, ]+))?", re.I)

# Quando a taint analysis confirma o fluxo, o achado heurístico da mesma linha é redundante.
SUPERSEDED_BY_TAINT = {
    "PY005": "TAINT-SQLI", "PY002": "TAINT-CODE", "PY003": "TAINT-CMDI", "PY004": "TAINT-DESER",
    "JS001": "TAINT-CODE", "JS002": "TAINT-XSS", "JS004": "TAINT-CMDI", "JS005": "TAINT-SQLI",
}


@dataclass
class ScanConfig:
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    disabled_rules: set[str] = field(default_factory=set)
    min_severity: Severity = Severity.INFO
    taint: bool = True
    bandit: bool = False
    semgrep: bool = False
    semgrep_config: str | None = None
    ignores: list[tuple[str, set[str]]] = field(default_factory=list)  # (glob do caminho, regras)

    @classmethod
    def load(cls, root: Path, **overrides) -> "ScanConfig":
        cfg = cls()
        path = root / ".sast.toml" if root.is_dir() else None
        if path and path.exists():
            data = tomllib.loads(path.read_text())
            cfg.exclude += data.get("exclude", [])
            cfg.disabled_rules |= set(data.get("disabled_rules", []))
            for item in data.get("ignore", []):
                if not item.get("reason"):
                    raise ValueError(f".sast.toml: exceção para {item.get('path')} precisa de 'reason'")
                cfg.ignores.append((item["path"], set(item.get("rules", []))))
            if "min_severity" in data:
                cfg.min_severity = Severity.parse(data["min_severity"])
        for key, value in overrides.items():
            if value is not None:
                setattr(cfg, key, value)
        return cfg


def _excluded(rel: str, patterns: list[str]) -> bool:
    parts = rel.replace("\\", "/").split("/")
    for pattern in patterns:
        pattern = pattern.rstrip("/")
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
        if fnmatch.fnmatch(rel, pattern) or rel.startswith(pattern + "/"):
            return True
    return False


def collect_files(root: Path, config: ScanConfig) -> dict[str, str]:
    """Lê os arquivos suportados. Retorna {caminho relativo: conteúdo}."""
    files: dict[str, str] = {}
    if root.is_file():
        files[root.name] = root.read_text(errors="replace")
        return files
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames if not _excluded(os.path.join(rel_dir, d), config.exclude)]
        for name in filenames:
            rel = os.path.join(rel_dir, name).replace("\\", "/")
            if Path(name).suffix not in LANG_BY_EXT or _excluded(rel, config.exclude):
                continue
            full = Path(dirpath) / name
            if full.is_symlink() or full.stat().st_size > MAX_FILE_BYTES:
                continue
            files[rel] = full.read_text(errors="replace")
    return files


def _suppressed(finding: Finding, lines_by_file: dict[str, list[str]], ignores=()) -> bool:
    for pattern, rules in ignores:
        if fnmatch.fnmatch(finding.file, pattern) and (not rules or finding.rule_id in rules):
            return True
    lines = lines_by_file.get(finding.file, [])
    for line_no in {finding.line, finding.end_line or finding.line}:
        if 1 <= line_no <= len(lines):
            match = SUPPRESS_RE.search(lines[line_no - 1])
            if match:
                ids = match.group(1) or match.group(2)
                if not ids:
                    return True
                if finding.rule_id in {i.strip() for i in ids.split(",")}:
                    return True
    return False


def run_python_rules(module: PythonModule, disabled: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(module.tree):  # uma única passada pela AST
        for rule_id, check in python_rules_for(node):
            if rule_id not in disabled:
                findings.extend(check(node, module))
    return findings


def deduplicate(findings: list[Finding]) -> list[Finding]:
    taint_lines = {(f.file, f.line, f.rule_id) for f in findings if f.rule_id.startswith("TAINT-")}
    seen: dict[tuple, Finding] = {}
    for f in findings:
        superseder = SUPERSEDED_BY_TAINT.get(f.rule_id)
        if superseder and (f.file, f.line, superseder) in taint_lines:
            continue
        key = (f.file, f.line, f.cwe or f.rule_id)
        current = seen.get(key)
        # mesma linha + mesma CWE vinda de motores diferentes: mantém o mais forte
        if current is None or (f.severity, f.confidence, f.engine.startswith("sast-engine")) > (
            current.severity, current.confidence, current.engine.startswith("sast-engine")
        ):
            if current is not None:
                f.extra.setdefault("also_reported_by", []).append(current.engine)
            seen[key] = f
        else:
            current.extra.setdefault("also_reported_by", []).append(f.engine)
    return sorted(seen.values(), key=lambda f: (-f.severity, f.file, f.line))


def scan_sources(files: dict[str, str], config: ScanConfig | None = None, root: Path | None = None) -> ScanResult:
    """Analisa um conjunto de arquivos em memória (usado pela CLI e pela API)."""
    config = config or ScanConfig()
    started = time.perf_counter()
    result = ScanResult()
    findings: list[Finding] = []
    modules: list[PythonModule] = []
    lines_by_file: dict[str, list[str]] = {}

    for path, source in sorted(files.items()):
        lang = LANG_BY_EXT.get(Path(path).suffix)
        if lang is None:
            continue
        lines_by_file[path] = source.splitlines()
        result.files_scanned += 1
        result.lines_scanned += len(lines_by_file[path])
        result.languages[lang] = result.languages.get(lang, 0) + 1
        if lang == "python":
            try:
                module = parse_python(path, source)
            except SyntaxError as exc:
                result.errors.append(ParseError(path, f"SyntaxError: {exc.msg}", exc.lineno or 0))
                continue
            modules.append(module)
            findings.extend(run_python_rules(module, config.disabled_rules))
        elif lang == "javascript" and javascript_ts.available():
            findings.extend(javascript_ts.scan_javascript(path, source))
            if config.taint:
                findings.extend(f for f in javascript_ts.taint_javascript(path, source) if f.rule_id not in config.disabled_rules)

    if config.taint and modules:
        findings.extend(f for f in TaintEngine(modules).run() if f.rule_id not in config.disabled_rules)

    if root is not None and config.bandit:
        findings.extend(integrations.run_bandit(root, config.exclude))
    if root is not None and config.semgrep:
        findings.extend(integrations.run_semgrep(root, config.semgrep_config, config.exclude))

    findings = [
        f for f in findings
        if f.severity >= config.min_severity and not _suppressed(f, lines_by_file, config.ignores)
    ]
    result.findings = deduplicate(findings)
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result


def scan_path(path: str | Path, config: ScanConfig | None = None) -> ScanResult:
    root = Path(path).resolve()
    config = config or ScanConfig.load(root)
    files = collect_files(root, config)
    return scan_sources(files, config, root=root if root.is_dir() else root.parent)
