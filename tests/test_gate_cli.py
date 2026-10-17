"""CLI, Security Gate, baseline e formatos de relatório."""
import json
from pathlib import Path

from sast_engine.cli import main

ROOT = Path(__file__).resolve().parent.parent
VULN = str(ROOT / "samples" / "vulnerable_app")
SAFE = str(ROOT / "samples" / "safe_app")


def test_gate_blocks_vulnerable_code(capsys):
    assert main(["scan", VULN, "--fail-on", "high"]) == 1
    assert "REPROVADO" in capsys.readouterr().out


def test_gate_passes_safe_code():
    assert main(["scan", SAFE, "--fail-on", "high"]) == 0


def test_without_fail_on_never_blocks():
    assert main(["scan", VULN, "--format", "json", "-o", "/dev/null"]) == 0


def test_baseline_only_new_findings_block(tmp_path):
    baseline = tmp_path / "base.json"
    main(["scan", VULN, "--format", "json", "-o", str(baseline)])
    assert main(["scan", VULN, "--fail-on", "high", "--baseline", str(baseline), "--format", "json", "-o", str(tmp_path / "r.json")]) == 0
    assert json.loads((tmp_path / "r.json").read_text())["gate"]["new_findings"] == 0


def test_sarif_is_valid_structure(tmp_path):
    out = tmp_path / "r.sarif"
    main(["scan", VULN, "--format", "sarif", "-o", str(out)])
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert any("codeFlows" in r for r in run["results"])
    assert all(float(r["properties"]["security-severity"]) > 0 for r in run["tool"]["driver"]["rules"])


def test_also_writes_extra_reports(tmp_path):
    md, sarif = tmp_path / "r.md", tmp_path / "r.sarif"
    main(["scan", VULN, "--format", "json", "-o", "/dev/null", "--also", f"markdown={md}", "--also", f"sarif={sarif}"])
    assert "Relatório SAST" in md.read_text() and sarif.exists()


def test_fingerprint_stable_when_lines_shift():
    from sast_engine.scanner import scan_sources
    a = scan_sources({"a.py": "def f(x):\n    eval(x)\n"}).findings[0]
    b = scan_sources({"a.py": "import os\n\n\ndef f(x):\n    eval(x)\n"}).findings[0]
    assert a.line != b.line and a.fingerprint == b.fingerprint


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    assert "TAINT-SQLI" in capsys.readouterr().out


def test_benchmark_precision_and_recall():
    import sys
    sys.path.insert(0, str(ROOT / "benchmark"))
    from run_benchmark import run
    report = run()
    assert report["precision"] >= 0.95 and report["recall"] >= 0.95
