from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

from ceres.analyzers.base import AnalyzerContext
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity


_SAFETY_EVAL_FALSE_KEYS = {
    "enablesafetyeval",
    "safetyevalenabled",
    "runsafetyeval",
    "requiresafetyeval",
    "safetygateenabled",
}
_SAFETY_EVAL_TRUE_KEYS = {
    "skipsafetyeval",
    "bypasssafetyeval",
    "disablesafetyeval",
    "allowsafetyevalfailure",
}
_REGRESSION_FALSE_KEYS = {
    "enableregressioneval",
    "regressionevalenabled",
    "runregressioneval",
    "requireregressioneval",
    "requireevalgate",
    "evalgateenabled",
}
_REGRESSION_TRUE_KEYS = {
    "skipregressioneval",
    "disableevalgate",
    "allowevalfailure",
}
_SAFETY_FILTER_FALSE_KEYS = {
    "enablecontentfilter",
    "contentfilter",
    "safetyfilter",
    "enablesafetyfilter",
    "guardrails",
    "enableguardrails",
    "outputredaction",
    "enableoutputredaction",
}
_CITATION_FALSE_KEYS = {
    "requirecitations",
    "citationsrequired",
    "enablecitations",
}
_THRESHOLD_KEYS = {
    "minsafetyscore",
    "safetyscorethreshold",
    "safetythreshold",
    "minsafetyevalscore",
    "mincontentfilterscore",
}
_TEMPERATURE_KEYS = {
    "temperature",
    "modeltemperature",
    "generationtemperature",
}
_EVAL_CONTEXT_RE = re.compile(r"(eval|safety|guardrail|moderation|content|redaction|risk)", re.IGNORECASE)


def run(ctx: AnalyzerContext) -> list[Finding]:
    findings: list[Finding] = []
    for path in ctx.inventory.configs:
        findings.extend(_scan_structured_file(path, ctx))
    for path in ctx.inventory.code:
        if path.suffix.lower() == ".py":
            findings.extend(_scan_python_file(path, ctx))
    return findings


def _scan_structured_file(path: Path, ctx: AnalyzerContext) -> list[Finding]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    suffix = path.suffix.lower()
    data: Any = None
    try:
        if suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        elif suffix == ".json":
            data = json.loads(raw)
        elif suffix == ".toml":
            data = tomllib.loads(raw)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError):
        return []

    findings: list[Finding] = []
    _walk_structured(data, ctx.rel(path), [], raw, findings, ctx)
    return findings


def _walk_structured(
    node: Any,
    rel: str,
    path: list[str],
    raw: str,
    out: list[Finding],
    ctx: AnalyzerContext,
) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            key_path = [*path, str(key)]
            _check_key_value(str(key), value, rel, key_path, _line_for_key(raw, str(key)), out, ctx)
            _walk_structured(value, rel, key_path, raw, out, ctx)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_structured(item, rel, [*path, f"[{i}]"], raw, out, ctx)


def _scan_python_file(path: Path, ctx: AnalyzerContext) -> list[Finding]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(raw, filename=str(path))
    except (OSError, SyntaxError):
        return []

    rel = ctx.rel(path)
    findings: list[Finding] = []

    class Visitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                key = _target_name(target)
                if key:
                    _check_key_value(key, _literal(node.value), rel, [key], node.lineno, findings, ctx)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            key = _target_name(node.target)
            if key:
                _check_key_value(key, _literal(node.value), rel, [key], node.lineno, findings, ctx)
            self.generic_visit(node)

        def visit_Dict(self, node: ast.Dict) -> None:
            for key_node, value_node in zip(node.keys, node.values):
                key = _literal(key_node)
                if isinstance(key, str):
                    _check_key_value(key, _literal(value_node), rel, [key], getattr(node, "lineno", None), findings, ctx)
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings


def _check_key_value(
    key: str,
    value: Any,
    rel: str,
    path: list[str],
    line: int | None,
    out: list[Finding],
    ctx: AnalyzerContext,
) -> None:
    normalized = _normalize(key)
    source = ".".join(path)
    preview = f"{key}={value!r}"
    epol = ctx.policy.eval_policy

    if epol.require_safety_eval:
        if normalized in _SAFETY_EVAL_FALSE_KEYS and value is False:
            out.append(_finding("ceres.eval.safety_eval_disabled", Severity.HIGH, rel, line, source, preview))
        if normalized in _SAFETY_EVAL_TRUE_KEYS and value is True:
            out.append(_finding("ceres.eval.safety_eval_disabled", Severity.HIGH, rel, line, source, preview))

    if epol.require_regression_eval:
        if normalized in _REGRESSION_FALSE_KEYS and value is False:
            out.append(_finding("ceres.eval.regression_gate_disabled", Severity.HIGH, rel, line, source, preview))
        if normalized in _REGRESSION_TRUE_KEYS and value is True:
            out.append(_finding("ceres.eval.regression_gate_disabled", Severity.HIGH, rel, line, source, preview))

    if epol.block_disabled_safety_filters and normalized in _SAFETY_FILTER_FALSE_KEYS and value is False:
        out.append(_finding("ceres.eval.safety_filter_disabled", Severity.HIGH, rel, line, source, preview))

    if normalized in _CITATION_FALSE_KEYS and value is False:
        out.append(
            Finding(
                rule_id="ceres.rag.citations_disabled",
                severity=Severity.MEDIUM,
                layer=Layer.RAG,
                file=rel,
                line=line,
                message="RAG response citations are disabled in configuration.",
                recommendation="Require citations for RAG responses that rely on retrieved context.",
                evidence=Evidence(source=source, matched_text_preview=preview[:160]),
                frameworks=FrameworkMap(owasp_llm=("LLM05",)),
            )
        )

    if normalized in _THRESHOLD_KEYS and isinstance(value, (int, float)) and value < epol.min_safety_score:
        out.append(
            Finding(
                rule_id="ceres.eval.safety_threshold_low",
                severity=Severity.HIGH,
                layer=Layer.EVAL,
                file=rel,
                line=line,
                message=f"Safety eval threshold {value:.2f} is below policy minimum {epol.min_safety_score:.2f}.",
                recommendation="Restore the threshold or update eval_policy.min_safety_score after review.",
                evidence=Evidence(source=source, matched_text_preview=preview[:160]),
                frameworks=FrameworkMap(owasp_llm=("LLM09",), owasp_ml=("ML09",)),
            )
        )

    if (
        normalized in _TEMPERATURE_KEYS
        and isinstance(value, (int, float))
        and value > epol.max_generation_temperature
        and _looks_eval_or_model_context(path)
    ):
        out.append(
            Finding(
                rule_id="ceres.eval.generation_temperature_high",
                severity=Severity.MEDIUM,
                layer=Layer.EVAL,
                file=rel,
                line=line,
                message=f"Generation temperature {value:.2f} exceeds policy maximum {epol.max_generation_temperature:.2f}.",
                recommendation="Use a lower temperature for safety-critical or retrieval-grounded workflows.",
                evidence=Evidence(source=source, matched_text_preview=preview[:160]),
                frameworks=FrameworkMap(owasp_llm=("LLM09",)),
            )
        )


def _finding(
    rule_id: str,
    severity: Severity,
    rel: str,
    line: int | None,
    source: str,
    preview: str,
) -> Finding:
    if rule_id == "ceres.eval.safety_eval_disabled":
        msg = "Safety eval gate is disabled or skipped."
        rec = "Keep safety evals required before model, prompt, adapter, or RAG deployment."
    elif rule_id == "ceres.eval.regression_gate_disabled":
        msg = "Regression eval gate is disabled or allowed to fail."
        rec = "Require regression evals before deploying AI behavior changes."
    else:
        msg = "Safety filter or guardrail is disabled."
        rec = "Keep content filters, guardrails, and output redaction enabled unless explicitly waived."
    return Finding(
        rule_id=rule_id,
        severity=severity,
        layer=Layer.EVAL,
        file=rel,
        line=line,
        message=msg,
        recommendation=rec,
        evidence=Evidence(source=source, matched_text_preview=preview[:160]),
        frameworks=FrameworkMap(owasp_llm=("LLM09",), owasp_ml=("ML09",)),
    )


def _target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _literal(node.slice) if isinstance(_literal(node.slice), str) else None
    return None


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return None


def _normalize(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", key.lower())


def _looks_eval_or_model_context(path: list[str]) -> bool:
    return any(_EVAL_CONTEXT_RE.search(p) for p in path) or len(path) <= 1


def _line_for_key(raw: str, key: str) -> int | None:
    needle = key.strip()
    for i, line in enumerate(raw.splitlines(), start=1):
        if needle and needle in line:
            return i
    return None
