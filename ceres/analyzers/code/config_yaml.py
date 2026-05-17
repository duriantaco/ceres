from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from ceres.analyzers.base import AnalyzerContext
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity

_HF_REPO_RE = re.compile(r"^[\w.\-]+/[\w.\-]+$")
_HF_PINNED_RE = re.compile(r"@[0-9a-fA-F]{7,}$")

_SHELL_KEYS = {"shell", "bash", "exec", "command", "system"}

_SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|secret|password|token|access[_-]?key|private[_-]?key|bearer|openai|anthropic)",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r"^(|<.+>|\{\{.+\}\}|\${.+}|\$\(.+\)|x{3,}|\.{3,}|todo|tbd|changeme|your[_-]?\w*|n/?a)$",
    re.IGNORECASE,
)
_HIGH_ENTROPY_RE = re.compile(r"^[A-Za-z0-9_\-]{24,}$")


def run(ctx: AnalyzerContext) -> list[Finding]:
    out: list[Finding] = []
    for path in (*ctx.inventory.configs, *ctx.inventory.prompts):
        out.extend(_scan_file(path, ctx))
    return out


def _scan_file(path: Path, ctx: AnalyzerContext) -> list[Finding]:
    rel = ctx.rel(path)
    findings: list[Finding] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    data: Any = None
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            data = None
    elif suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None

    if data is not None:
        _walk(data, rel, [], findings, ctx)

    if ctx.policy.code_policy.scan_inline_secrets:
        for i, line in enumerate(raw.splitlines(), start=1):
            m = _line_secret(line)
            if m:
                findings.append(
                    Finding(
                        rule_id="ceres.prompt.secret_literal",
                        severity=Severity.HIGH,
                        layer=Layer.PROMPT if path in ctx.inventory.prompts else Layer.CODE,
                        file=rel,
                        line=i,
                        message=f"Likely secret in {path.suffix or 'config'} value.",
                        recommendation="Use Skylos for generic secret scanning; keep AI prompts/configs free of inline credentials.",
                        evidence=Evidence(matched_text_preview=line.strip()[:160]),
                        frameworks=FrameworkMap(owasp_llm=("LLM06",)),
                    )
                )

    return findings


def _line_secret(line: str) -> bool:
    if ":" not in line and "=" not in line:
        return False
    sep_idx = max(line.find(":"), line.find("="))
    key = line[:sep_idx].strip().strip("\"'")
    val = line[sep_idx + 1 :].strip().strip(",").strip("\"'")
    if not _SECRET_NAME_RE.search(key):
        return False
    if not val or _PLACEHOLDER_RE.match(val) or val.startswith(("$", "{{", "${")):
        return False
    if len(val) < 16:
        return False
    return bool(_HIGH_ENTROPY_RE.match(val))


def _walk(node: Any, rel: str, path: list[str], out: list[Finding], ctx: AnalyzerContext) -> None:
    if isinstance(node, dict):
        mpol = ctx.policy.model_policy
        if "tools" in node and isinstance(node["tools"], dict):
            for tool_name, body in node["tools"].items():
                if not isinstance(body, dict):
                    continue
                if any(k in tool_name.lower() for k in _SHELL_KEYS) and body.get("enabled", False):
                    allowlist = body.get("allowlist") or body.get("allowed_commands")
                    if allowlist in (None, "*", ["*"]):
                        out.append(
                            Finding(
                                rule_id="ceres.agent.tool.shell_without_allowlist",
                                severity=Severity.CRITICAL,
                                layer=Layer.AGENT,
                                file=rel,
                                message=f"Agent tool '{tool_name}' has unrestricted shell access.",
                                recommendation="Add an explicit allowlist of safe commands, or disable shell.",
                                evidence=Evidence(source=".".join([*path, "tools", tool_name])),
                                frameworks=FrameworkMap(owasp_llm=("LLM07", "LLM08")),
                            )
                        )

        for k in ("model", "model_name", "model_id", "base_model", "base_model_name_or_path"):
            if k in node and isinstance(node[k], str):
                v = node[k]
                if (
                    mpol.require_known_source
                    and mpol.approved_model_sources
                    and _looks_like_model_source(v)
                    and not _source_allowed(v, mpol.approved_model_sources)
                ):
                    out.append(
                        Finding(
                            rule_id="ceres.model.artifact.source_missing_or_unapproved",
                            severity=Severity.HIGH,
                            layer=Layer.MODEL,
                            file=rel,
                            message=f"Model source '{v}' is not in approved_model_sources.",
                            recommendation="Use an approved model source or update model_policy.approved_model_sources after review.",
                            evidence=Evidence(source=".".join([*path, k]), matched_text_preview=v),
                            frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05")),
                        )
                    )
                if _HF_REPO_RE.match(v) and not _HF_PINNED_RE.search(v) and "revision" not in node:
                    out.append(
                        Finding(
                            rule_id="ceres.model.config.revision_unpinned",
                            severity=Severity.HIGH,
                            layer=Layer.MODEL,
                            file=rel,
                            message=f"Hugging Face model reference '{v}' is not pinned to a revision.",
                            recommendation="Add a 'revision: <commit-sha>' alongside the model reference.",
                            evidence=Evidence(source=".".join([*path, k]), matched_text_preview=v),
                            frameworks=FrameworkMap(owasp_llm=("LLM03",)),
                        )
                    )

        for k, v in node.items():
            _walk(v, rel, [*path, str(k)], out, ctx)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, rel, [*path, f"[{i}]"], out, ctx)


def _looks_like_model_source(value: str) -> bool:
    return _HF_REPO_RE.match(value) is not None or value.startswith(("hf://", "s3://", "https://", "http://"))


def _source_allowed(source: str, approved: list[str]) -> bool:
    normalized = source.strip()
    hf_url = f"huggingface.co/{normalized}"
    return any(normalized.startswith(prefix) or hf_url.startswith(prefix) for prefix in approved)
