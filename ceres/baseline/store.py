from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Any

from ceres.analyzers.agent.tool_poisoning import descriptor_baseline, extract_tool_descriptors
from ceres.analyzers.data.fingerprint import fingerprint
from ceres.analyzers.model.gguf_static import gguf_baseline_for
from ceres.analyzers.model.onnx_static import onnx_baseline_for
from ceres.analyzers.model.safetensors_static import tensor_baseline_for
from ceres.inventory.walker import Inventory


def build_baseline(inv: Inventory) -> dict[str, Any]:
    models: dict[str, Any] = {}
    for path in inv.models:
        rel = _rel(path, inv.root)
        entry: dict[str, Any] = {"sha256": _sha256(path)}
        if path.suffix.lower() == ".safetensors":
            tensor_baseline = tensor_baseline_for(path)
            if tensor_baseline is not None:
                entry.update(tensor_baseline)
        if path.suffix.lower() == ".gguf":
            gguf_baseline = gguf_baseline_for(path)
            if gguf_baseline is not None:
                entry.update(gguf_baseline)
        if path.suffix.lower() == ".onnx":
            onnx_baseline = onnx_baseline_for(path)
            if onnx_baseline is not None:
                entry.update(onnx_baseline)
        if path.suffix.lower() == ".json":
            tokens = _try_tokens(path)
            if tokens is not None:
                entry["tokens"] = tokens
            if path.name == "tokenizer_config.json":
                ct = _try_chat_template(path)
                if ct is not None:
                    entry["chat_template"] = ct
            if path.name == "adapter_config.json":
                base = _try_adapter_base(path)
                if base is not None:
                    entry["base_model_name_or_path"] = base
        models[rel] = entry

    datasets: dict[str, Any] = {}
    for path in inv.datasets:
        fp = fingerprint(path)
        if fp is None:
            continue
        datasets[_rel(path, inv.root)] = {
            "sha256": fp.sha256,
            "row_count": fp.row_count,
            "duplicate_rate": fp.duplicate_rate,
            "label_distribution": fp.label_distribution,
            "top_ngrams": fp.top_ngrams,
            "columns": fp.columns,
        }

    rag: dict[str, Any] = {}
    if inv.rag_docs:
        rag["doc_count"] = len(inv.rag_docs)
        rag["docs"] = sorted(_rel(p, inv.root) for p in inv.rag_docs)

    tools = descriptor_baseline(extract_tool_descriptors(inv.configs, inv.code, inv.root))

    return {
        "version": 1,
        "created_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "models": models,
        "datasets": datasets,
        "rag": rag,
        "tools": tools,
    }


def save_baseline(baseline: dict[str, Any], out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2, sort_keys=True))
    return out


def load_baseline(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _try_tokens(path: Path) -> list[str] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return sorted(_extract_strings(data))


def _try_chat_template(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, dict):
        v = data.get("chat_template")
        return v if isinstance(v, str) else None
    return None


def _try_adapter_base(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, dict):
        v = data.get("base_model_name_or_path")
        return v if isinstance(v, str) else None
    return None


def _extract_strings(data: Any) -> list[str]:
    out: list[str] = []
    if isinstance(data, dict):
        for v in data.values():
            out.extend(_extract_strings(v))
    elif isinstance(data, list):
        for v in data:
            out.extend(_extract_strings(v))
    elif isinstance(data, str):
        out.append(data)
    return out
