from __future__ import annotations

import datetime as _dt
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from ceres.inventory.walker import Inventory


def build_bom(inv: Inventory) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for path in inv.models:
        components.append(_model_component(path, inv.root))
    for path in inv.datasets:
        components.append(_dataset_component(path, inv.root))
    for path in inv.prompts:
        components.append(_prompt_component(path, inv.root))

    return {
        "bomFormat": "CeresAI-BOM",
        "specVersion": "1.0",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": [{"name": "ceres", "vendor": "ceres", "version": _ceres_version()}],
        },
        "components": components,
    }


def _ceres_version() -> str:
    from ceres import __version__

    return __version__


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _model_component(path: Path, root: Path) -> dict[str, Any]:
    return {
        "type": "machine-learning-model",
        "name": path.stem,
        "version": "unknown",
        "hashes": [{"alg": "SHA-256", "content": _hash(path)}],
        "properties": [
            {"name": "ceres:path", "value": _rel(path, root)},
            {"name": "ceres:format", "value": path.suffix.lstrip(".") or "binary"},
        ],
    }


def _dataset_component(path: Path, root: Path) -> dict[str, Any]:
    return {
        "type": "data",
        "name": path.stem,
        "version": "unknown",
        "hashes": [{"alg": "SHA-256", "content": _hash(path)}],
        "properties": [
            {"name": "ceres:path", "value": _rel(path, root)},
            {"name": "ceres:format", "value": path.suffix.lstrip(".") or "data"},
        ],
    }


def _prompt_component(path: Path, root: Path) -> dict[str, Any]:
    return {
        "type": "file",
        "name": path.name,
        "version": "unknown",
        "hashes": [{"alg": "SHA-256", "content": _hash(path)}],
        "properties": [
            {"name": "ceres:path", "value": _rel(path, root)},
            {"name": "ceres:kind", "value": "prompt"},
        ],
    }


def write_bom(inv: Inventory, out: Path) -> Path:
    bom = build_bom(inv)
    out.write_text(json.dumps(bom, indent=2))
    return out


def check_bom_coverage(inv: Inventory, bom_path: Path | None) -> list[str]:
    if bom_path is None or not bom_path.exists():
        if inv.models or inv.datasets:
            return ["No ai-bom.json present despite models/datasets in the repo."]
        return []
    try:
        bom = json.loads(bom_path.read_text())
    except (OSError, json.JSONDecodeError):
        return ["ai-bom.json is unreadable."]
    listed_paths = {
        prop["value"]
        for c in bom.get("components", [])
        for prop in c.get("properties", [])
        if prop.get("name") == "ceres:path"
    }
    missing = []
    for path in (*inv.models, *inv.datasets):
        rel = _rel(path, inv.root)
        if rel not in listed_paths:
            missing.append(rel)
    return [f"AI-BOM missing component: {p}" for p in missing]
