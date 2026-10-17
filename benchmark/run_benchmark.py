"""Mede precisão, recall e F1 do motor contra o ground truth anotado nas amostras.

Ground truth: comentários `# expect: REGRA [REGRA...]` (ou `// expect:` em JS) na
linha onde o achado deve aparecer. Linhas sem anotação não devem gerar achados.

Uso:  python benchmark/run_benchmark.py [--json resultado.json] [--min-precision 0.9]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sast_engine.scanner import ScanConfig, scan_path  # noqa: E402

EXPECT_RE = re.compile(r"(?:#|//)\s*expect:\s*([A-Z0-9\- ]+)")
SAMPLES = ROOT / "samples"


def ground_truth(base: Path) -> set[tuple[str, int, str]]:
    expected = set()
    for path in base.rglob("*"):
        if path.suffix not in {".py", ".js"}:
            continue
        rel = path.relative_to(base).as_posix()
        for n, line in enumerate(path.read_text().splitlines(), 1):
            match = EXPECT_RE.search(line)
            if match:
                for rule in match.group(1).split():
                    expected.add((rel, n, rule))
    return expected


def run(engine_taint: bool = True) -> dict:
    result = scan_path(SAMPLES, ScanConfig(taint=engine_taint))
    found = {(f.file, f.line, f.rule_id) for f in result.findings}
    expected = ground_truth(SAMPLES)

    tp, fp, fn = found & expected, found - expected, expected - found
    precision = len(tp) / len(found) if found else 1.0
    recall = len(tp) / len(expected) if expected else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    per_rule: dict[str, dict[str, int]] = {}
    for bucket, items in (("tp", tp), ("fp", fp), ("fn", fn)):
        for _, _, rule in items:
            per_rule.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0})[bucket] += 1

    return {
        "files": result.files_scanned,
        "lines": result.lines_scanned,
        "duration_ms": result.duration_ms,
        "expected": len(expected),
        "found": len(found),
        "true_positives": len(tp),
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "per_rule": dict(sorted(per_rule.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="salva o resultado em JSON")
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--min-recall", type=float, default=0.0)
    args = parser.parse_args()

    report = run()
    no_taint = run(engine_taint=False)
    report["ablation_without_taint"] = {k: no_taint[k] for k in ("precision", "recall", "f1", "true_positives")}

    print(f"Arquivos: {report['files']}  Linhas: {report['lines']}  Tempo: {report['duration_ms']} ms")
    print(f"Esperados: {report['expected']}  Encontrados: {report['found']}  VP: {report['true_positives']}")
    print(f"Precisão: {report['precision']:.1%}  Recall: {report['recall']:.1%}  F1: {report['f1']:.3f}")
    a = report["ablation_without_taint"]
    print(f"Sem taint analysis -> Precisão: {a['precision']:.1%}  Recall: {a['recall']:.1%}  F1: {a['f1']:.3f}")
    for label, key in (("Falsos positivos", "false_positives"), ("Falsos negativos", "false_negatives")):
        if report[key]:
            print(f"\n{label}:")
            for file, line, rule in report[key]:
                print(f"  {rule:15} {file}:{line}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    ok = report["precision"] >= args.min_precision and report["recall"] >= args.min_recall
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
