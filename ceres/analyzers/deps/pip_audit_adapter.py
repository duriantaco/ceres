from __future__ import annotations

import json
import shutil
import subprocess

from ceres.analyzers.base import AnalyzerContext
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity


def run(ctx: AnalyzerContext) -> list[Finding]:
    if not ctx.policy.dependency_policy.run_pip_audit:
        return []
    if shutil.which("pip-audit") is None:
        return []

    req_files = [
        p for p in ctx.inventory.dependencies
        if p.name in {"requirements.txt", "requirements-dev.txt", "pyproject.toml"}
    ]
    if not req_files:
        return []

    findings: list[Finding] = []
    for req in req_files:
        cmd = ["pip-audit", "--format", "json"]
        if req.name in {"requirements.txt", "requirements-dev.txt"}:
            cmd += ["-r", str(req)]
        else:
            cmd += ["--project-path", str(req.parent)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if not result.stdout.strip():
            continue
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            continue

        deps = data.get("dependencies") if isinstance(data, dict) else data
        if not isinstance(deps, list):
            continue
        rel = ctx.rel(req)
        for dep in deps:
            vulns = dep.get("vulns") or []
            for v in vulns:
                severity = _severity_for(v)
                findings.append(
                    Finding(
                        rule_id="ceres.supplychain.vulnerable_dependency",
                        severity=severity,
                        layer=Layer.DEPS,
                        file=rel,
                        message=(
                            f"{dep.get('name')} {dep.get('version')}: "
                            f"{v.get('id')} {v.get('description', '')[:80]}"
                        ),
                        recommendation=(
                            f"Upgrade to a fixed release: {', '.join(v.get('fix_versions', []) or ['(no fix listed)'])}"
                        ),
                        evidence=Evidence(extra={"advisory_id": v.get("id"), "package": dep.get("name")}),
                        frameworks=FrameworkMap(owasp_llm=("LLM05",)),
                    )
                )
    return findings


def _severity_for(vuln: dict) -> Severity:
    sev = (vuln.get("severity") or "").lower()
    if sev in ("critical",):
        return Severity.CRITICAL
    if sev in ("high",):
        return Severity.HIGH
    if sev in ("medium", "moderate"):
        return Severity.MEDIUM
    if sev in ("low",):
        return Severity.LOW
    return Severity.MEDIUM
