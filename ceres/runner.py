from __future__ import annotations

from pathlib import Path

from ceres.analyzers.base import AnalyzerContext
from ceres.analyzers.agent import tool_poisoning
from ceres.analyzers.bom.aibom import check_bom_coverage
from ceres.analyzers.code import config_yaml as code_config
from ceres.analyzers.code import python_ast
from ceres.analyzers.data import manifest as data_manifest
from ceres.analyzers.deps import static as deps_static
from ceres.analyzers.deps import gitleaks_adapter, pip_audit_adapter
from ceres.analyzers.model import scanner as model_scanner
from ceres.analyzers.prompt import prompt_rules
from ceres.analyzers.rag import text_extract as rag_extract
from ceres.baseline.store import load_baseline
from ceres.config import Policy
from ceres.findings.model import Finding, Layer, Severity
from ceres.findings.severity import gate
from ceres.findings.waivers import apply_waivers, parse_waivers
from ceres.inventory.walker import Inventory, build_inventory


ANALYZERS = [
    ("code.python_ast", python_ast.run),
    ("code.config_yaml", code_config.run),
    ("agent.tool_poisoning", tool_poisoning.run),
    ("model.scanner", model_scanner.run),
    ("data.manifest", data_manifest.run),
    ("rag.text", rag_extract.run),
    ("prompt.rules", prompt_rules.run),
    ("deps.static", deps_static.run),
    ("deps.pip_audit", pip_audit_adapter.run),
    ("deps.gitleaks", gitleaks_adapter.run),
]


def run_scan(
    root: Path,
    policy: Policy,
    baseline_path: Path | None,
    bom_path: Path | None = None,
) -> tuple[list[Finding], list[Finding], dict[str, int], bool, Inventory]:
    inv = build_inventory(root)
    baseline = load_baseline(baseline_path)
    ctx = AnalyzerContext(root=root.resolve(), inventory=inv, policy=policy, baseline=baseline)

    findings: list[Finding] = []
    for _name, fn in ANALYZERS:
        try:
            findings.extend(fn(ctx))
        except Exception as e:  # noqa: BLE001
            findings.append(
                Finding(
                    rule_id="ceres.engine.analyzer_failed",
                    severity=Severity.HIGH,
                    layer=Layer.POLICY,
                    file="<scanner>",
                    message=f"Analyzer {_name} failed: {e}",
                    recommendation="Treat this scan as incomplete and report the analyzer failure as a bug.",
                )
            )

    for gap in check_bom_coverage(inv, bom_path):
        findings.append(
            Finding(
                rule_id="ceres.aibom.coverage_missing",
                severity=Severity.LOW,
                layer=Layer.BOM,
                file="ai-bom.json",
                message=gap,
                recommendation="Run `ceres bom --out ai-bom.json` to (re)generate the AI-BOM.",
            )
        )

    waivers = parse_waivers(policy.waivers)
    kept, suppressed, expired = apply_waivers(findings, waivers)
    for w in expired:
        kept.append(
            Finding(
                rule_id="ceres.policy.waiver_expired",
                severity=Severity.MEDIUM,
                layer=Layer.POLICY,
                file=w.file or "<policy>",
                message=f"Waiver for {w.rule_id} expired on {w.expires}.",
                recommendation="Renew or remove the waiver in ceres.yml.",
            )
        )

    passed, counts = gate(kept, policy.severity_gate.as_dict())
    return kept, suppressed, counts, passed, inv
