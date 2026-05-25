from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from ceres.analyzers.base import AnalyzerContext
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]


_LOCKFILES = {
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "requirements.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
}
_MANIFESTS = {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "package.json", "Cargo.toml", "go.mod"}
_GIT_SHA_RE = re.compile(r"@[0-9a-fA-F]{40}(?:[?#].*)?$")
_REQ_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?")
_EXACT_PIN_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?\s*(?:==|===)\s*[^=].+")
_REMOTE_SCRIPT_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]+\|\s*(?:sh|bash|python|python3)\b")


def run(ctx: AnalyzerContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_external_scanners(ctx))
    findings.extend(_check_lockfile(ctx))
    for dep_file in ctx.inventory.dependencies:
        if dep_file.name in {"requirements.txt", "requirements-dev.txt"}:
            findings.extend(_scan_requirements(dep_file, ctx))
        elif dep_file.name == "pyproject.toml":
            findings.extend(_scan_pyproject(dep_file, ctx))
    for ci_file in ctx.inventory.ci:
        findings.extend(_scan_ci_or_docker(ci_file, ctx))
    return findings


def _check_external_scanners(ctx: AnalyzerContext) -> list[Finding]:
    manifests = [p for p in ctx.inventory.dependencies if p.name in _MANIFESTS]
    findings: list[Finding] = []
    if manifests and ctx.policy.dependency_policy.run_osv_scanner and shutil.which("osv-scanner") is None:
        findings.append(_scanner_unavailable(ctx, manifests[0], "osv-scanner"))
    if manifests and ctx.policy.dependency_policy.run_pip_audit and shutil.which("pip-audit") is None:
        findings.append(_scanner_unavailable(ctx, manifests[0], "pip-audit"))
    if (
        (ctx.inventory.prompts or ctx.inventory.configs)
        and ctx.policy.dependency_policy.run_gitleaks
        and shutil.which("gitleaks") is None
    ):
        file_ = (ctx.inventory.prompts or ctx.inventory.configs)[0]
        findings.append(_scanner_unavailable(ctx, file_, "gitleaks"))
    return findings


def _scanner_unavailable(ctx: AnalyzerContext, path: Path, tool: str) -> Finding:
    return Finding(
        rule_id="ceres.supplychain.scanner_unavailable",
        severity=Severity.LOW,
        layer=Layer.DEPS,
        file=ctx.rel(path),
        message=f"Policy enables {tool}, but it is not installed on PATH.",
        recommendation=f"Install {tool} in CI, or disable the integration in dependency_policy after review.",
        frameworks=FrameworkMap(owasp_llm=("LLM05",)),
    )


def _check_lockfile(ctx: AnalyzerContext) -> list[Finding]:
    if not ctx.policy.dependency_policy.require_lockfile:
        return []
    manifests = [p for p in ctx.inventory.dependencies if p.name in _MANIFESTS]
    if not manifests:
        return []
    if any(p.name in _LOCKFILES for p in ctx.inventory.dependencies):
        return []
    first = manifests[0]
    return [
        Finding(
            rule_id="ceres.supplychain.lockfile_missing",
            severity=Severity.MEDIUM,
            layer=Layer.DEPS,
            file=ctx.rel(first),
            message="Dependency manifest exists without a lockfile.",
            recommendation="Commit a lockfile so CI resolves the same dependency graph every run.",
            frameworks=FrameworkMap(owasp_llm=("LLM05",)),
        )
    ]


def _scan_requirements(path: Path, ctx: AnalyzerContext) -> list[Finding]:
    out: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for lineno, raw in enumerate(lines, start=1):
        line = _strip_req_comment(raw).strip()
        if not line or line.startswith(("-", "#")):
            continue
        if line.startswith("git+") or " git+" in line:
            if not _GIT_SHA_RE.search(line):
                out.append(_git_unpinned_finding(ctx, path, lineno, raw.strip()))
            continue
        if (
            ctx.policy.dependency_policy.scan_unpinned_dependencies
            and _REQ_NAME_RE.match(line)
            and not _EXACT_PIN_RE.match(line)
        ):
            out.append(_unpinned_finding(ctx, path, lineno, raw.strip()))
    return out


def _strip_req_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _scan_pyproject(path: Path, ctx: AnalyzerContext) -> list[Finding]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []
    out: list[Finding] = []
    deps = []
    project = data.get("project") if isinstance(data, dict) else {}
    if isinstance(project, dict):
        deps.extend(project.get("dependencies") or [])
        optional = project.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    deps.extend(values)
    for dep in deps:
        if not isinstance(dep, str):
            continue
        if dep.strip().startswith("git+") and not _GIT_SHA_RE.search(dep.strip()):
            out.append(_git_unpinned_finding(ctx, path, None, dep))
        elif ctx.policy.dependency_policy.scan_unpinned_dependencies and _looks_unpinned_dep(dep):
            out.append(_unpinned_finding(ctx, path, None, dep))

    poetry_deps = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    if ctx.policy.dependency_policy.scan_unpinned_dependencies and isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            if _poetry_spec_unpinned(spec):
                out.append(_unpinned_finding(ctx, path, None, f"{name} = {spec!r}"))
    return out


def _looks_unpinned_dep(dep: str) -> bool:
    dep = dep.strip()
    if dep.startswith(("git+", "http://", "https://")):
        return not _GIT_SHA_RE.search(dep)
    return _REQ_NAME_RE.match(dep) is not None and _EXACT_PIN_RE.match(dep) is None


def _poetry_spec_unpinned(spec: Any) -> bool:
    if isinstance(spec, str):
        return spec in {"*", "latest"} or not spec.startswith("==")
    if isinstance(spec, dict):
        version = spec.get("version")
        return version is None or _poetry_spec_unpinned(version)
    return False


def _unpinned_finding(ctx: AnalyzerContext, path: Path, lineno: int | None, preview: str) -> Finding:
    return Finding(
        rule_id="ceres.supplychain.dependency_unpinned",
        severity=Severity.LOW,
        layer=Layer.DEPS,
        file=ctx.rel(path),
        line=lineno,
        message="Dependency is not pinned to an exact version.",
        recommendation="Use exact pins or a lockfile-backed workflow for reproducible builds.",
        evidence=Evidence(matched_text_preview=preview[:160]),
        frameworks=FrameworkMap(owasp_llm=("LLM05",)),
    )


def _git_unpinned_finding(ctx: AnalyzerContext, path: Path, lineno: int | None, preview: str) -> Finding:
    return Finding(
        rule_id="ceres.supplychain.git_dependency_unpinned",
        severity=Severity.HIGH,
        layer=Layer.DEPS,
        file=ctx.rel(path),
        line=lineno,
        message="Git dependency is not pinned to a full commit SHA.",
        recommendation="Pin git dependencies with @<40-char-commit-sha>.",
        evidence=Evidence(matched_text_preview=preview[:160]),
        frameworks=FrameworkMap(owasp_llm=("LLM05",)),
    )


def _scan_ci_or_docker(path: Path, ctx: AnalyzerContext) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = ctx.rel(path)
    out: list[Finding] = []
    for m in _REMOTE_SCRIPT_RE.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        out.append(
            Finding(
                rule_id="ceres.supplychain.remote_script_pipe",
                severity=Severity.HIGH,
                layer=Layer.DEPS,
                file=rel,
                line=lineno,
                message="CI/Docker config pipes a remote download directly into an interpreter.",
                recommendation="Download, verify checksum/signature, then execute from a pinned source.",
                evidence=Evidence(matched_text_preview=_line(text, lineno)),
                frameworks=FrameworkMap(owasp_llm=("LLM05",)),
            )
        )
    if path.name.lower() == "dockerfile" or path.suffix.lower() == ".dockerfile":
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue
            image = stripped.split()[1]
            if image.lower() == "scratch" or "@sha256:" in image:
                continue
            out.append(
                Finding(
                    rule_id="ceres.supplychain.docker_image_unpinned",
                    severity=Severity.MEDIUM,
                    layer=Layer.DEPS,
                    file=rel,
                    line=lineno,
                    message=f"Docker base image '{image}' is not pinned by digest.",
                    recommendation="Pin Docker images with @sha256:<digest>.",
                    evidence=Evidence(matched_text_preview=stripped[:160]),
                    frameworks=FrameworkMap(owasp_llm=("LLM05",)),
                )
            )
    return out


def _line(text: str, lineno: int) -> str:
    lines = text.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""
