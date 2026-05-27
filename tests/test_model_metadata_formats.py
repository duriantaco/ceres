from __future__ import annotations

import pickle
import struct
import zipfile
from pathlib import Path
from typing import Any

from ceres.baseline.store import build_baseline, save_baseline
from ceres.config import Policy
from ceres.inventory.walker import build_inventory
from ceres.runner import run_scan


REAL_ONNX_ADD_MODEL = bytes.fromhex(
    # Official ONNX backend test fixture:
    # onnx/backend/test/data/node/test_add/model.onnx
    "0807120c6261636b656e642d746573743a690a100a01780a0179120373756d"
    "22034164641208746573745f6164645a170a017812120a100801120c0a0208"
    "030a0208040a0208055a170a017912120a100801120c0a0208030a0208040a"
    "02080562190a0373756d12120a100801120c0a0208030a0208040a020805"
    "42040a00100e"
)


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
    findings, _suppressed, _counts, _passed, _inv = run_scan(
        repo,
        policy or _policy(),
        baseline,
        repo / "ai-bom.json",
    )
    return {f.rule_id for f in findings}


def _findings(repo: Path, baseline: Path | None = None, policy: Policy | None = None):
    findings, _suppressed, _counts, _passed, _inv = run_scan(
        repo,
        policy or _policy(),
        baseline,
        repo / "ai-bom.json",
    )
    return findings


def _gguf_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def _gguf_value(value: Any) -> bytes:
    if isinstance(value, str):
        return struct.pack("<I", 8) + _gguf_string(value)
    if isinstance(value, bool):
        return struct.pack("<I?", 7, value)
    if isinstance(value, int):
        return struct.pack("<IQ", 10, value)
    if isinstance(value, float):
        return struct.pack("<Id", 12, value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        out = [struct.pack("<IIQ", 9, 8, len(value))]
        out.extend(_gguf_string(item) for item in value)
        return b"".join(out)
    raise TypeError(f"unsupported GGUF test value: {value!r}")


def _write_gguf(
    path: Path,
    metadata: dict[str, Any],
    tensors: list[tuple[str, list[int], int, int]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    chunks = [b"GGUF", struct.pack("<IQQ", 3, len(tensors), len(metadata))]
    for key, value in metadata.items():
        chunks.append(_gguf_string(key))
        chunks.append(_gguf_value(value))
    for name, shape, tensor_type, offset in tensors:
        chunks.append(_gguf_string(name))
        chunks.append(struct.pack("<I", len(shape)))
        chunks.extend(struct.pack("<Q", dim) for dim in shape)
        chunks.append(struct.pack("<IQ", tensor_type, offset))
    path.write_bytes(b"".join(chunks))


def _pb_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _pb_key(field: int, wire_type: int) -> bytes:
    return _pb_varint((field << 3) | wire_type)


def _pb_int(field: int, value: int) -> bytes:
    return _pb_key(field, 0) + _pb_varint(value)


def _pb_str(field: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return _pb_key(field, 2) + _pb_varint(len(raw)) + raw


def _pb_msg(field: int, value: bytes) -> bytes:
    return _pb_key(field, 2) + _pb_varint(len(value)) + value


def _write_onnx(
    path: Path,
    *,
    opset: int = 17,
    nodes: list[str] | None = None,
    producer: str = "ceres-tests",
    producer_version: str = "1",
    metadata: dict[str, str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    nodes = nodes or ["MatMul"]
    metadata = metadata or {"source": "unit-test"}
    graph = [_pb_str(2, "unit-graph")]
    for op_type in nodes:
        graph.append(_pb_msg(1, _pb_str(4, op_type)))
    opset_msg = _pb_str(1, "") + _pb_int(2, opset)
    chunks = [
        _pb_int(1, 8),
        _pb_str(2, producer),
        _pb_str(3, producer_version),
        _pb_msg(7, b"".join(graph)),
        _pb_msg(8, opset_msg),
    ]
    for key, value in metadata.items():
        chunks.append(_pb_msg(14, _pb_str(1, key) + _pb_str(2, value)))
    path.write_bytes(b"".join(chunks))


def test_gguf_baseline_captures_static_metadata(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.gguf"
    _write_gguf(
        model,
        {
            "general.architecture": "llama",
            "general.name": "unit",
            "tokenizer.ggml.tokens": ["<s>", "</s>"],
        },
        [("blk.0.weight", [2, 2], 0, 0)],
    )

    baseline = build_baseline(build_inventory(repo))
    entry = baseline["models"]["models/model.gguf"]
    assert entry["format"] == "gguf"
    assert entry["version"] == 3
    assert entry["tensor_count"] == 1
    assert entry["metadata"]["general.architecture"] == "llama"
    assert entry["metadata"]["tokenizer.ggml.tokens"]["length"] == 2
    assert entry["tensors"]["blk.0.weight"]["type"] == "F32"


def test_gguf_invalid_header_is_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "bad.gguf"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"GGUF")

    assert "ceres.model.gguf.header_invalid" in _rule_ids(repo)


def test_gguf_oversized_metadata_is_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.gguf"
    _write_gguf(model, {"general.name": "larger-than-test-limit"}, [])
    pol = _policy()
    pol.model_policy.max_gguf_string_bytes = 4

    assert "ceres.model.gguf.metadata_oversized" in _rule_ids(repo, policy=pol)


def test_gguf_metadata_drift_is_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.gguf"
    _write_gguf(
        model,
        {"general.architecture": "llama", "general.name": "unit"},
        [("blk.0.weight", [2, 2], 0, 0)],
    )
    baseline = _baseline(repo)
    _write_gguf(
        model,
        {"general.architecture": "qwen", "general.name": "unit"},
        [
            ("blk.0.weight", [2, 2], 0, 0),
            ("blk.1.weight", [2, 2], 0, 16),
        ],
    )

    rule_ids = _rule_ids(repo, baseline)
    assert "ceres.model.gguf.architecture_drift" in rule_ids
    assert "ceres.model.gguf.metadata_drift" in rule_ids
    assert "ceres.model.gguf.tensor_count_drift" in rule_ids


def test_onnx_baseline_captures_static_metadata(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.onnx"
    _write_onnx(model, nodes=["MatMul", "Relu"], metadata={"source": "unit-test"})

    baseline = build_baseline(build_inventory(repo))
    entry = baseline["models"]["models/model.onnx"]
    assert entry["format"] == "onnx"
    assert entry["ir_version"] == 8
    assert entry["opset_imports"] == {"": 17}
    assert entry["node_op_counts"] == {"MatMul": 1, "Relu": 1}
    assert entry["metadata_props"] == {"source": "unit-test"}


def test_real_onnx_backend_fixture_is_parsed(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.onnx"
    model.parent.mkdir(parents=True)
    model.write_bytes(REAL_ONNX_ADD_MODEL)

    baseline = build_baseline(build_inventory(repo))
    entry = baseline["models"]["models/model.onnx"]
    assert entry["format"] == "onnx"
    assert entry["ir_version"] == 7
    assert entry["producer_name"] == "backend-test"
    assert entry["graph_name"] == "test_add"
    assert entry["opset_imports"] == {"": 14}
    assert entry["node_op_counts"] == {"Add": 1}


def test_onnx_invalid_protobuf_is_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "bad.onnx"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"\x0a\xff")

    assert "ceres.model.onnx.header_invalid" in _rule_ids(repo)


def test_truncated_real_onnx_fixture_is_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "bad.onnx"
    model.parent.mkdir(parents=True)
    model.write_bytes(REAL_ONNX_ADD_MODEL[:16])

    assert "ceres.model.onnx.header_invalid" in _rule_ids(repo)


def test_onnx_oversized_metadata_is_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.onnx"
    _write_onnx(model, producer="larger-than-test-limit")
    pol = _policy()
    pol.model_policy.max_onnx_string_bytes = 4

    assert "ceres.model.onnx.metadata_oversized" in _rule_ids(repo, policy=pol)


def test_onnx_metadata_and_operator_drift_are_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.onnx"
    _write_onnx(model, opset=17, nodes=["MatMul"], producer_version="1")
    baseline = _baseline(repo)
    _write_onnx(model, opset=18, nodes=["MatMul", "Relu"], producer_version="2")

    rule_ids = _rule_ids(repo, baseline)
    assert "ceres.model.onnx.opset_drift" in rule_ids
    assert "ceres.model.onnx.operator_drift" in rule_ids
    assert "ceres.model.onnx.metadata_drift" in rule_ids


def test_non_pickle_pt_checkpoint_is_not_reported_as_pickle_risk(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "bad.pt"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"not a valid torch checkpoint")

    findings = _findings(repo)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "ceres.model.artifact.pickle_opcode_risk" not in by_rule
    assert "ceres.model.artifact.format_not_allowed" in by_rule


def test_risky_pt_pickle_checkpoint_is_flagged(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "risky.pt"
    model.parent.mkdir(parents=True)
    model.write_bytes(pickle.dumps(__import__("os").system))

    findings = _findings(repo)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "ceres.model.artifact.pickle_opcode_risk" in by_rule
    assert by_rule["ceres.model.artifact.pickle_opcode_risk"].severity.value == "critical"


def test_zip_backed_pt_data_pickle_is_scanned(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "checkpoint.pt"
    model.parent.mkdir(parents=True)
    with zipfile.ZipFile(model, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(__import__("os").system))

    findings = _findings(repo)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "ceres.model.artifact.pickle_opcode_risk" in by_rule
    assert by_rule["ceres.model.artifact.pickle_opcode_risk"].severity.value == "critical"
