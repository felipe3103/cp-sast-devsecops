"""Linha de comando do SentinelaSAST.

Exemplos:
    python -m sast_engine scan .                         # relatório no terminal
    python -m sast_engine scan . --fail-on high          # Security Gate (exit 1 se reprovar)
    python -m sast_engine scan . --format sarif -o sast.sarif
    python -m sast_engine scan . --ai                    # triagem com Ollama/Llama 3
    python -m sast_engine rules                          # catálogo de regras
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from . import __version__, reporters
from .gate import GatePolicy, evaluate
from .models import Confidence, Severity
from .rules.catalog import CATALOG
from .scanner import ScanConfig, scan_path

EXIT_OK, EXIT_GATE_FAILED, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinela", description="SentinelaSAST - análise estática de segurança")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analisa um diretório ou arquivo")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--format", choices=["text", "json", "sarif", "markdown", "gitlab"], default="text")
    scan.add_argument("-o", "--output", help="arquivo de saída (padrão: stdout)")
    scan.add_argument("--also", action="append", default=[], metavar="FORMATO=ARQUIVO",
                      help="gera relatórios extras, ex.: --also sarif=sast.sarif --also markdown=sast.md")
    scan.add_argument("--fail-on", type=str.upper, choices=[s.name for s in Severity], default=None,
                      help="ativa o Security Gate: falha se houver achado com essa severidade ou maior")
    scan.add_argument("--min-confidence", type=str.upper, choices=[c.name for c in Confidence], default="MEDIUM")
    scan.add_argument("--max-findings", type=int, default=None)
    scan.add_argument("--baseline", help="relatório JSON anterior: só achados novos contam para o gate")
    scan.add_argument("--min-severity", type=str.upper, choices=[s.name for s in Severity], default=None)
    scan.add_argument("--exclude", action="append", default=[], help="padrão glob a ignorar (repetível)")
    scan.add_argument("--disable", action="append", default=[], help="desativa uma regra (repetível)")
    scan.add_argument("--no-taint", action="store_true", help="desliga a taint analysis")
    scan.add_argument("--bandit", action="store_true", help="incorpora resultados do Bandit")
    scan.add_argument("--semgrep", action="store_true", help="incorpora resultados do Semgrep")
    scan.add_argument("--ai", action="store_true", help="triagem e remediação com LLM local (Ollama)")
    scan.add_argument("--ai-semantic", action="store_true",
                      help="varredura semântica: o LLM procura falhas de lógica que as regras não pegam")
    scan.add_argument("--ai-limit", type=int, default=20, help="máximo de achados enviados à IA")
    scan.add_argument("--upload", metavar="URL", help="envia o resultado para a API da plataforma")
    scan.add_argument("--project", default=None, help="nome do projeto ao enviar para a API")

    sub.add_parser("rules", help="lista o catálogo de regras")
    return parser


def _ai_enrich(result, root: Path, limit: int) -> None:
    from .ai import AITriage

    triage = AITriage()
    if not triage.client.is_available():
        print(f"⚠ Ollama indisponível em {triage.client.base_url}; usando base de conhecimento.", file=sys.stderr)
    project_files = {
        f.file: (root / f.file).read_text(errors="replace")
        for f in result.findings if (root / f.file).is_file()
    }
    for finding in result.findings[:limit]:
        source = project_files.get(finding.file, finding.snippet)
        analysis = triage.analyze(finding, source, project_files)
        finding.extra["ai"] = analysis.to_dict()
        if analysis.suppressed:
            finding.extra["ai_suppressed"] = True
        if analysis.source == "llm":
            finding.severity = Severity.parse(analysis.severity)


def _ai_semantic(result, root: Path) -> None:
    from .ai import AITriage
    from .scanner import ScanConfig, collect_files, deduplicate

    triage = AITriage()
    known = list(result.findings)
    config = ScanConfig.load(root if root.is_dir() else root.parent)
    for path, source in collect_files(root, config).items():
        language = "python" if path.endswith(".py") else "javascript"
        print(f"… varredura semântica: {path}", file=sys.stderr)
        result.findings.extend(triage.semantic_review(path, source, language, known))
    result.findings = deduplicate(result.findings)


def _upload(url: str, payload: dict) -> None:
    import os

    from .ai.ollama_client import require_http_url

    require_http_url(url)
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-API-Token": os.getenv("SAST_API_TOKEN", "")},
    )
    try:
        # esquema http(s) garantido por require_http_url
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
            print(f"Resultado enviado para a plataforma (HTTP {resp.status}).", file=sys.stderr)
    except Exception as exc:  # o upload não deve quebrar o pipeline
        print(f"⚠ Falha ao enviar resultado: {exc}", file=sys.stderr)


def cmd_scan(args) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Caminho não encontrado: {root}", file=sys.stderr)
        return EXIT_ERROR
    config = ScanConfig.load(root if root.is_dir() else root.parent)
    config.exclude += args.exclude
    config.disabled_rules |= set(args.disable)
    config.taint = not args.no_taint
    config.bandit, config.semgrep = args.bandit, args.semgrep
    if args.min_severity:
        config.min_severity = Severity.parse(args.min_severity)

    result = scan_path(root, config)
    base = root if root.is_dir() else root.parent
    if args.ai:
        _ai_enrich(result, base, args.ai_limit)
    if args.ai_semantic:
        _ai_semantic(result, root)

    gate = None
    if args.fail_on:
        policy = GatePolicy(
            fail_on=Severity.parse(args.fail_on),
            min_confidence=Confidence.parse(args.min_confidence),
            max_findings=args.max_findings,
            baseline=GatePolicy.load_baseline(args.baseline) if args.baseline else None,
        )
        gate = evaluate(result.findings, policy)

    render = {
        "text": lambda: reporters.to_text(result, gate),
        "json": lambda: reporters.to_json(result, gate),
        "sarif": lambda: reporters.to_sarif(result),
        "markdown": lambda: reporters.to_markdown(result, gate),
        "gitlab": lambda: reporters.to_gitlab_sast(result),
    }
    output = render[args.format]()
    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)
    for extra in args.also:
        fmt, _, dest = extra.partition("=")
        if fmt in render and dest:
            Path(dest).write_text(render[fmt]())

    if args.upload:
        payload = json.loads(reporters.to_json(result, gate))
        payload["project"] = args.project or base.name
        _upload(args.upload, payload)

    if gate and args.format != "text":
        print(("❌ SECURITY GATE REPROVADO: " if gate["failed"] else "✅ Security Gate aprovado: ") + gate["reason"], file=sys.stderr)
    return EXIT_GATE_FAILED if gate and gate["failed"] else EXIT_OK


def cmd_rules() -> int:
    for meta in CATALOG.values():
        print(f"{meta.id:15} {meta.severity.name:8} {meta.cwe:8} {meta.kind:13} {meta.title}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return cmd_rules()
    return cmd_scan(args)
