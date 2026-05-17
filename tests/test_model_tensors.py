from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from ceres.baseline.store import build_baseline, save_baseline
from ceres.config import Policy
from ceres.inventory.walker import build_inventory
from ceres.runner import run_scan


def _write_safetensors(path: Path, tensors: dict[str, tuple[str, list[int], bytes]]) -> None:
    offset = 0
    header = {}
    chunks = []
    for name, (dtype, shape, data) in tensors.items():
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [offset, offset + len(data)]}
        chunks.append(data)
        offset += len(data)
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + b"".join(chunks))


def _f32(*values: float) -> bytes:
    return struct.pack("<" + ("f" * len(values)), *values)


def _policy() -> Policy:
    pol = Policy()
    pol.model_policy.require_known_source = False
    pol.dependency_policy.run_pip_audit = False
    pol.dependency_policy.run_gitleaks = False
    return pol


def _baseline(repo: Path) -> Path:
    out = repo / ".ceres" / "baseline.json"
    save_baseline(build_baseline(build_inventory(repo)), out)
    return out


def _rule_ids(repo: Path, baseline: Path | None = None, policy: Policy | None = None) -> set[str]:
    findings, _suppressed, _counts, _passed, _inv = run_scan(repo, policy or _policy(), baseline, repo / "ai-bom.json")
    return {f.rule_id for f in findings}


def test_safetensors_baseline_captures_tensor_metadata(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(model, {"layer.weight": ("F32", [2], b"\x00" * 8)})

    baseline = build_baseline(build_inventory(repo))
    entry = baseline["models"]["models/model.safetensors"]
    tensor = entry["tensors"]["layer.weight"]
    assert entry["format"] == "safetensors"
    assert entry["tensor_count"] == 1
    assert tensor["dtype"] == "F32"
    assert tensor["shape"] == [2]
    assert tensor["byte_length"] == 8
    assert len(tensor["sha256"]) == 64
    assert tensor["stats"]["count"] == 2
    assert tensor["stats"]["zero_count"] == 2
    assert tensor["stats"]["zero_ratio"] == 1.0
    assert tensor["stats"]["l2_norm"] == 0.0


def test_safetensors_baseline_captures_tensor_stats(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(model, {"layer.weight": ("F32", [3], _f32(0.0, 3.0, 4.0))})

    baseline = build_baseline(build_inventory(repo))
    stats = baseline["models"]["models/model.safetensors"]["tensors"]["layer.weight"]["stats"]
    assert stats["count"] == 3
    assert stats["finite_count"] == 3
    assert stats["zero_count"] == 1
    assert stats["zero_ratio"] == pytest.approx(1 / 3)
    assert stats["min"] == 0.0
    assert stats["max"] == 4.0
    assert stats["mean"] == pytest.approx(7 / 3)
    assert stats["l2_norm"] == pytest.approx(5.0)


def test_safetensors_unchanged_model_has_no_tensor_drift(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    _write_safetensors(models / "model.safetensors", {"layer.weight": ("F32", [2], b"\x00" * 8)})
    baseline = _baseline(repo)

    rule_ids = _rule_ids(repo, baseline)
    assert not {r for r in rule_ids if r.startswith("ceres.model.tensor.")}


def test_safetensors_tensor_hash_changed(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(model, {"layer.weight": ("F32", [2], b"\x00" * 8)})
    baseline = _baseline(repo)
    _write_safetensors(model, {"layer.weight": ("F32", [2], b"\x01" * 8)})

    assert "ceres.model.tensor.hash_drift" in _rule_ids(repo, baseline)


def test_safetensors_tensor_nan_or_inf(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(model, {"layer.weight": ("F32", [3], _f32(0.0, float("nan"), float("inf")))})

    assert "ceres.model.tensor.nan_or_inf" in _rule_ids(repo)


def test_safetensors_tensor_norm_and_sparsity_drift(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(model, {"layer.weight": ("F32", [4], _f32(0.0, 0.0, 1.0, 1.0))})
    baseline = _baseline(repo)
    _write_safetensors(model, {"layer.weight": ("F32", [4], _f32(0.0, 10.0, 10.0, 10.0))})

    rule_ids = _rule_ids(repo, baseline)
    assert "ceres.model.tensor.norm_drift" in rule_ids
    assert "ceres.model.tensor.sparsity_drift" in rule_ids


def test_safetensors_tensor_range_anomaly(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(model, {"layer.weight": ("F32", [2], _f32(1.0, 10.0))})
    pol = _policy()
    pol.model_policy.max_tensor_abs_value = 5.0

    assert "ceres.model.tensor.range_anomaly" in _rule_ids(repo, policy=pol)


def test_safetensors_tensor_shape_dtype_added_removed(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(
        model,
        {
            "layer.weight": ("F32", [2], b"\x00" * 8),
            "old.weight": ("F32", [1], b"\x00" * 4),
        },
    )
    baseline = _baseline(repo)
    _write_safetensors(
        model,
        {
            "layer.weight": ("F32", [3], b"\x00" * 12),
            "dtype.weight": ("F16", [2], b"\x00" * 4),
            "admin_trigger.weight": ("F32", [1], b"\x00" * 4),
        },
    )

    rule_ids = _rule_ids(repo, baseline)
    assert "ceres.model.tensor.shape_changed" in rule_ids
    assert "ceres.model.tensor.added" in rule_ids
    assert "ceres.model.tensor.removed" in rule_ids
    assert "ceres.model.tensor.suspicious_name" in rule_ids


def test_safetensors_tensor_dtype_changed(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "model.safetensors"
    _write_safetensors(model, {"layer.weight": ("F32", [2], b"\x00" * 8)})
    baseline = _baseline(repo)
    _write_safetensors(model, {"layer.weight": ("I32", [2], b"\x00" * 8)})

    assert "ceres.model.tensor.dtype_changed" in _rule_ids(repo, baseline)


def test_safetensors_invalid_and_oversized_headers(tmp_path):
    repo = tmp_path / "repo"
    models = repo / "models"
    models.mkdir(parents=True)
    model = models / "bad.safetensors"
    model.write_bytes(struct.pack("<Q", 4) + b"nope")

    assert "ceres.model.safetensors.header_invalid" in _rule_ids(repo)

    pol = _policy()
    pol.model_policy.max_safetensors_header_bytes = 2
    _write_safetensors(model, {"layer.weight": ("F32", [1], b"\x00" * 4)})
    assert "ceres.model.safetensors.header_oversized" in _rule_ids(repo, policy=pol)
