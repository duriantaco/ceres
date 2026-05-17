from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ceres.analyzers.base import AnalyzerContext
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity


def run(ctx: AnalyzerContext) -> list[Finding]:
    if not ctx.policy.dependency_policy.run_gitleaks:
        return []
    if shutil.which("gitleaks") is None:
        return []

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "gitleaks.json"
        cmd = [
            "gitleaks",
            "detect",
            "--no-git",
            "--no-banner",
            "--redact",
            "--report-format",
            "json",
            "--report-path",
            str(out),
            "--source",
            str(ctx.root),
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        if not out.exists():
            return []
        try:
            data = json.loads(out.read_text())
        except json.JSONDecodeError:
            return []

    findings: list[Finding] = []
    for hit in data or []:
        file_ = hit.get("File") or hit.get("file") or ""
        line = hit.get("StartLine") or hit.get("startLine")
        rule = hit.get("RuleID") or hit.get("ruleID") or "secret"
        findings.append(
            Finding(
                rule_id=f"ceres.supplychain.secret_scanner_hit.{rule}",
                severity=Severity.CRITICAL,
                layer=Layer.DEPS,
                file=file_,
                line=line,
                message=f"Gitleaks detected '{rule}' secret.",
                recommendation="Rotate the secret immediately, scrub it from history, and move it to a secrets manager.",
                evidence=Evidence(matched_text_preview=(hit.get("Match") or "")[:120]),
                frameworks=FrameworkMap(owasp_llm=("LLM06",)),
            )
        )
    return findings
