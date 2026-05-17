from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import yaml

from ceres.analyzers.base import AnalyzerContext
from ceres.analyzers.model.pickle_static import scan_path
from ceres.analyzers.model.safetensors_static import SafetensorsInfo, inspect_safetensors
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity

_FORMAT_BY_EXT = {
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".joblib": "pickle",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".bin": "pytorch",
    ".ckpt": "pytorch",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".h5": "h5",
    ".keras": "keras",
    ".pb": "tensorflow",
    ".gguf": "gguf",
}
_SOURCE_KEYS = {
    "source",
    "model",
    "model_id",
    "model_name",
    "model_name_or_path",
    "_name_or_path",
    "base_model",
    "base_model_name_or_path",
    "repo",
    "repository",
}


def run(ctx: AnalyzerContext) -> list[Finding]:
    findings: list[Finding] = []
    mpol = ctx.policy.model_policy
    baseline_models = (ctx.baseline or {}).get("models", {}) if ctx.baseline else {}

    for path in ctx.inventory.models:
        rel = ctx.rel(path)
        suffix = path.suffix.lower()
        fmt = _FORMAT_BY_EXT.get(suffix)
        if fmt is None:
            # tokenizer/config json files — handled below
            findings.extend(_check_tokenizer_metadata(path, ctx, baseline_models))
            continue

        if fmt == "safetensors" and mpol.scan_safetensors_tensors:
            findings.extend(_scan_safetensors(path, ctx, baseline_models, rel))

        allowed = {f.lower().lstrip(".") for f in mpol.allowed_formats}
        format_names = {fmt, suffix.lstrip(".")}
        if allowed and not (format_names & allowed) and fmt != "pickle":
            findings.append(
                Finding(
                    rule_id="ceres.model.artifact.format_not_allowed",
                    severity=Severity.HIGH,
                    layer=Layer.MODEL,
                    file=rel,
                    message=f"Model artifact format '{suffix}' is not in the allowed format list.",
                    recommendation="Use an approved safe format, or update model_policy.allowed_formats with an explicit review.",
                    evidence=Evidence(extra={"format": fmt, "allowed_formats": sorted(allowed)}),
                    frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05"), owasp_ml=("ML06",)),
                )
            )

        # Blocked / risky serialization formats
        blocked = {b.lower().lstrip(".") for b in mpol.blocked_formats}
        if fmt == "pickle" and (blocked & {"pkl", "pickle"}):
            findings.append(
                Finding(
                    rule_id="ceres.model.artifact.pickle_format",
                    severity=Severity.CRITICAL,
                    layer=Layer.MODEL,
                    file=rel,
                    message="Pickle-based model artifact may execute code during deserialization.",
                    recommendation="Re-export as safetensors or ONNX, or require signed/provenanced artifacts.",
                    frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05"), owasp_ml=("ML06",)),
                )
            )

        if mpol.require_known_source:
            source = _find_source_metadata(path)
            if source is None:
                findings.append(
                    Finding(
                        rule_id="ceres.model.artifact.source_missing_or_unapproved",
                        severity=Severity.HIGH,
                        layer=Layer.MODEL,
                        file=rel,
                        message="Model artifact has no adjacent source/provenance metadata.",
                        recommendation="Add model source metadata or include the model in a reviewed AI-BOM/model manifest.",
                        frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05"), owasp_ml=("ML06",)),
                    )
                )
            elif mpol.approved_model_sources and not _source_allowed(source, mpol.approved_model_sources):
                findings.append(
                    Finding(
                        rule_id="ceres.model.artifact.source_missing_or_unapproved",
                        severity=Severity.HIGH,
                        layer=Layer.MODEL,
                        file=rel,
                        message=f"Model source '{source}' is not in approved_model_sources.",
                        recommendation="Use an approved model registry/source or update policy after review.",
                        evidence=Evidence(matched_text_preview=source),
                        frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05"), owasp_ml=("ML06",)),
                    )
                )

        # Pytorch checkpoint without safe-format alternative
        if fmt in {"pytorch", "pickle"}:
            scan = scan_path(path)
            if scan is not None:
                if scan.is_dangerous:
                    findings.append(
                        Finding(
                            rule_id="ceres.model.artifact.pickle_opcode_risk",
                            severity=Severity.CRITICAL,
                            layer=Layer.MODEL,
                            file=rel,
                            message=(
                                "Static pickle scan flagged suspicious imports/opcodes: "
                                f"{', '.join(scan.suspicious_globals[:5]) or scan.error}"
                            ),
                            recommendation="Do NOT load this artifact. Investigate provenance and rebuild from a trusted source.",
                            evidence=Evidence(extra={"opcodes": scan.opcode_count, "has_reduce": scan.has_reduce}),
                            frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05"), owasp_ml=("ML06",)),
                        )
                    )

        # Format preference: nudge toward safetensors
        if fmt == "pytorch":
            findings.append(
                Finding(
                    rule_id="ceres.model.artifact.prefer_safetensors",
                    severity=Severity.MEDIUM,
                    layer=Layer.MODEL,
                    file=rel,
                    message=f"{suffix} model artifact — consider migrating to safetensors.",
                    recommendation="Re-export weights with safetensors to eliminate deserialization risk.",
                    frameworks=FrameworkMap(owasp_ml=("ML06",)),
                )
            )

        # Hash + source requirements
        if mpol.require_sha256:
            sha = _sha256_file(path)
            baseline = baseline_models.get(rel) or {}
            expected = baseline.get("sha256")
            if expected and expected != sha:
                findings.append(
                    Finding(
                        rule_id="ceres.model.artifact.hash_drift",
                        severity=Severity.HIGH,
                        layer=Layer.MODEL,
                        file=rel,
                        message="Model artifact hash differs from baseline.",
                        recommendation="Confirm the change is expected; bump baseline and update the AI-BOM.",
                        evidence=Evidence(extra={"expected_sha256": expected, "actual_sha256": sha}),
                        frameworks=FrameworkMap(owasp_ml=("ML06",)),
                    )
                )

    return findings


def _scan_safetensors(path: Path, ctx: AnalyzerContext, baseline_models: dict, rel: str) -> list[Finding]:
    mpol = ctx.policy.model_policy
    result = inspect_safetensors(
        path,
        max_header_bytes=mpol.max_safetensors_header_bytes,
        max_tensor_hash_bytes=mpol.max_tensor_hash_bytes,
        max_tensor_stat_bytes=mpol.max_tensor_stat_bytes,
        hash_block_size=mpol.tensor_hash_block_size,
        stat_block_size=mpol.tensor_stat_block_size,
        hash_tensors=True,
        compute_stats=True,
    )
    if not result.ok or result.info is None:
        rule = result.error_code or "ceres.model.safetensors.header_invalid"
        return [
            Finding(
                rule_id=rule,
                severity=Severity.HIGH,
                layer=Layer.MODEL,
                file=rel,
                message=result.error or "Safetensors metadata could not be parsed.",
                recommendation="Re-export the model from a trusted source and verify the safetensors file structure.",
                frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05"), owasp_ml=("ML06",)),
            )
        ]

    out: list[Finding] = []
    out.extend(_suspicious_tensor_names(result.info, rel, mpol.suspicious_tensor_name_patterns))
    out.extend(_suspicious_tensor_stats(result.info, rel, mpol))
    baseline = baseline_models.get(rel) or {}
    baseline_tensors = baseline.get("tensors") or {}
    if isinstance(baseline_tensors, dict) and baseline_tensors:
        out.extend(_compare_tensors(result.info, baseline_tensors, rel, mpol))
    return out


def _suspicious_tensor_names(info: SafetensorsInfo, rel: str, patterns: list[str]) -> list[Finding]:
    lowered = [p.lower() for p in patterns if p]
    out: list[Finding] = []
    for name in sorted(info.tensors):
        lname = name.lower()
        matched = [p for p in lowered if p in lname]
        if not matched:
            continue
        out.append(
            Finding(
                rule_id="ceres.model.tensor.suspicious_name",
                severity=Severity.LOW,
                layer=Layer.MODEL,
                file=rel,
                message=f"Tensor/layer name contains suspicious marker text: {name}",
                recommendation="Review whether this tensor name is expected; combine with baseline drift before treating as high risk.",
                evidence=Evidence(extra={"tensor": name, "matched_patterns": matched}),
                frameworks=FrameworkMap(owasp_ml=("ML06",)),
                confidence=0.5,
            )
        )
    return out


def _suspicious_tensor_stats(info: SafetensorsInfo, rel: str, mpol: Any) -> list[Finding]:
    out: list[Finding] = []
    for name in sorted(info.tensors):
        tensor = info.tensors[name]
        if tensor.stats is None:
            continue
        stats = tensor.stats
        if stats.nan_count or stats.inf_count:
            out.append(
                _tensor_finding(
                    "ceres.model.tensor.nan_or_inf",
                    Severity.HIGH,
                    rel,
                    name,
                    "Tensor contains NaN or infinite values.",
                    "Rebuild the artifact from a trusted checkpoint and confirm the tensor values are expected.",
                    {
                        "nan_count": stats.nan_count,
                        "inf_count": stats.inf_count,
                        "count": stats.count,
                    },
                )
            )

        max_abs = _max_abs(stats.min, stats.max)
        if max_abs is not None and max_abs > mpol.max_tensor_abs_value:
            out.append(
                _tensor_finding(
                    "ceres.model.tensor.range_anomaly",
                    Severity.MEDIUM,
                    rel,
                    name,
                    "Tensor value range exceeds the configured absolute-value limit.",
                    "Review the checkpoint for corruption, quantization mistakes, or suspicious weight injection.",
                    {
                        "min": stats.min,
                        "max": stats.max,
                        "max_abs": max_abs,
                        "limit": mpol.max_tensor_abs_value,
                    },
                )
            )
    return out


def _compare_tensors(info: SafetensorsInfo, baseline_tensors: dict, rel: str, mpol: Any) -> list[Finding]:
    current = info.tensors
    current_names = set(current)
    baseline_names = set(baseline_tensors)
    out: list[Finding] = []

    for name in sorted(current_names - baseline_names):
        tensor = current[name]
        out.append(
            _tensor_finding(
                "ceres.model.tensor.added",
                Severity.MEDIUM,
                rel,
                name,
                "New tensor/layer appeared compared with baseline.",
                "Confirm the model architecture change is expected and update the baseline after review.",
                {"current": tensor.to_baseline()},
            )
        )

    for name in sorted(baseline_names - current_names):
        out.append(
            _tensor_finding(
                "ceres.model.tensor.removed",
                Severity.HIGH,
                rel,
                name,
                "Tensor/layer disappeared compared with baseline.",
                "Confirm the model architecture change is expected and update the baseline after review.",
                {"baseline": baseline_tensors[name]},
            )
        )

    for name in sorted(current_names & baseline_names):
        tensor = current[name]
        prev = baseline_tensors.get(name) or {}
        prev_shape = prev.get("shape")
        cur_shape = list(tensor.shape)
        if prev_shape and prev_shape != cur_shape:
            out.append(
                _tensor_finding(
                    "ceres.model.tensor.shape_changed",
                    Severity.HIGH,
                    rel,
                    name,
                    "Tensor/layer shape changed compared with baseline.",
                    "Review the architecture diff; shape changes can indicate swapped heads, adapters, or incompatible weights.",
                    {"baseline_shape": prev_shape, "current_shape": cur_shape},
                )
            )
        prev_dtype = prev.get("dtype")
        if prev_dtype and prev_dtype != tensor.dtype:
            out.append(
                _tensor_finding(
                    "ceres.model.tensor.dtype_changed",
                    Severity.MEDIUM,
                    rel,
                    name,
                    "Tensor/layer dtype changed compared with baseline.",
                    "Confirm the dtype conversion is expected and update the baseline after review.",
                    {"baseline_dtype": prev_dtype, "current_dtype": tensor.dtype},
                )
            )
        prev_hash = prev.get("sha256")
        if prev_hash and tensor.sha256 and prev_hash != tensor.sha256:
            out.append(
                _tensor_finding(
                    "ceres.model.tensor.hash_drift",
                    Severity.MEDIUM,
                    rel,
                    name,
                    "Tensor bytes changed compared with baseline.",
                    "Review model provenance and training changes before accepting the new tensor hash.",
                    {"baseline_sha256": prev_hash, "current_sha256": tensor.sha256},
                )
            )
        if tensor.stats is not None:
            out.extend(_compare_tensor_stats(tensor.name, tensor.stats.to_baseline(), prev.get("stats"), rel, mpol))
    return out


def _compare_tensor_stats(
    name: str,
    current_stats: dict[str, Any],
    baseline_stats: Any,
    rel: str,
    mpol: Any,
) -> list[Finding]:
    if not isinstance(baseline_stats, dict):
        return []

    out: list[Finding] = []
    cur_norm = _as_float(current_stats.get("l2_norm"))
    prev_norm = _as_float(baseline_stats.get("l2_norm"))
    if cur_norm is not None and prev_norm is not None:
        drift = _relative_drift(cur_norm, prev_norm)
        if drift > mpol.tensor_norm_drift_ratio:
            out.append(
                _tensor_finding(
                    "ceres.model.tensor.norm_drift",
                    Severity.MEDIUM,
                    rel,
                    name,
                    "Tensor L2 norm changed sharply compared with baseline.",
                    "Review training provenance and model diff before accepting this weight change.",
                    {
                        "baseline_l2_norm": prev_norm,
                        "current_l2_norm": cur_norm,
                        "relative_drift": drift,
                        "threshold": mpol.tensor_norm_drift_ratio,
                    },
                )
            )

    cur_zero = _as_float(current_stats.get("zero_ratio"))
    prev_zero = _as_float(baseline_stats.get("zero_ratio"))
    if cur_zero is not None and prev_zero is not None:
        drift = abs(cur_zero - prev_zero)
        if drift > mpol.tensor_sparsity_drift_ratio:
            out.append(
                _tensor_finding(
                    "ceres.model.tensor.sparsity_drift",
                    Severity.MEDIUM,
                    rel,
                    name,
                    "Tensor sparsity changed sharply compared with baseline.",
                    "Review pruning, quantization, or adapter changes before accepting the new baseline.",
                    {
                        "baseline_zero_ratio": prev_zero,
                        "current_zero_ratio": cur_zero,
                        "absolute_drift": drift,
                        "threshold": mpol.tensor_sparsity_drift_ratio,
                    },
                )
            )
    return out


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _relative_drift(current: float, baseline: float) -> float:
    return abs(current - baseline) / max(abs(baseline), 1e-12)


def _max_abs(a: float | None, b: float | None) -> float | None:
    values = [abs(v) for v in (a, b) if v is not None]
    return max(values) if values else None


def _tensor_finding(
    rule_id: str,
    severity: Severity,
    rel: str,
    tensor: str,
    message: str,
    recommendation: str,
    extra: dict[str, Any],
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        layer=Layer.MODEL,
        file=rel,
        message=f"{message} Tensor: {tensor}",
        recommendation=recommendation,
        evidence=Evidence(extra={"tensor": tensor, **extra}),
        frameworks=FrameworkMap(owasp_ml=("ML06",)),
    )


def _check_tokenizer_metadata(path: Path, ctx: AnalyzerContext, baseline_models: dict) -> list[Finding]:
    name = path.name
    if name not in {"tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "added_tokens.json", "adapter_config.json"}:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    rel = ctx.rel(path)
    out: list[Finding] = []
    baseline = baseline_models.get(rel) or {}

    if name in {"special_tokens_map.json", "added_tokens.json"}:
        cur_tokens = sorted(_extract_tokens(data))
        prev_tokens = sorted(baseline.get("tokens", []))
        if prev_tokens and cur_tokens != prev_tokens:
            new = sorted(set(cur_tokens) - set(prev_tokens))
            if new:
                out.append(
                    Finding(
                        rule_id="ceres.model.tokenizer.special_token_drift",
                        severity=Severity.HIGH,
                        layer=Layer.MODEL,
                        file=rel,
                        message=f"New special token(s) since baseline: {', '.join(new[:5])}",
                        recommendation="Confirm the new tokens are expected; they can hide backdoors.",
                        frameworks=FrameworkMap(owasp_ml=("ML06",)),
                    )
                )

    if name == "tokenizer_config.json":
        ct = data.get("chat_template")
        prev_ct = baseline.get("chat_template")
        if prev_ct and ct and ct != prev_ct:
            out.append(
                Finding(
                    rule_id="ceres.model.chat_template.drift",
                    severity=Severity.HIGH,
                    layer=Layer.MODEL,
                    file=rel,
                    message="Chat template changed compared to baseline.",
                    recommendation="Review chat template diff; injected instructions can persist here.",
                    frameworks=FrameworkMap(owasp_llm=("LLM01",)),
                )
            )

    if name == "adapter_config.json":
        base = data.get("base_model_name_or_path")
        prev_base = baseline.get("base_model_name_or_path")
        if prev_base and base and prev_base != base:
            out.append(
                Finding(
                    rule_id="ceres.model.lora.base_model_drift",
                    severity=Severity.HIGH,
                    layer=Layer.MODEL,
                    file=rel,
                    message=f"LoRA adapter base model changed: '{prev_base}' -> '{base}'.",
                    recommendation="Confirm the base model swap is intentional and the adapter is compatible.",
                    frameworks=FrameworkMap(owasp_ml=("ML06",)),
                )
            )

    return out


def _extract_tokens(data) -> list[str]:
    if isinstance(data, dict):
        out: list[str] = []
        for v in data.values():
            out.extend(_extract_tokens(v))
        return out
    if isinstance(data, list):
        out = []
        for v in data:
            out.extend(_extract_tokens(v))
        return out
    if isinstance(data, str):
        return [data]
    return []


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_source_metadata(path: Path) -> str | None:
    candidates = [
        path.with_suffix(".json"),
        path.parent / "model.json",
        path.parent / "model.yaml",
        path.parent / "model.yml",
        path.parent / "config.json",
        path.parent / "adapter_config.json",
    ]
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.exists() or candidate == path:
            continue
        seen.add(candidate)
        data = _load_metadata(candidate)
        if data is None:
            continue
        source = _extract_source(data)
        if source:
            return source
    return None


def _load_metadata(path: Path) -> Any | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        if path.suffix.lower() == ".json":
            return json.loads(raw)
        if path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(raw)
    except (json.JSONDecodeError, yaml.YAMLError):
        return None
    return None


def _extract_source(data: Any) -> str | None:
    if isinstance(data, dict):
        for key, value in data.items():
            if key in _SOURCE_KEYS and isinstance(value, str) and value.strip():
                return value.strip()
        for value in data.values():
            found = _extract_source(value)
            if found:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _extract_source(value)
            if found:
                return found
    return None


def _source_allowed(source: str, approved: list[str]) -> bool:
    normalized = source.strip()
    hf_url = f"huggingface.co/{normalized}"
    return any(normalized.startswith(prefix) or hf_url.startswith(prefix) for prefix in approved)
