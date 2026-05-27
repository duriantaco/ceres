from __future__ import annotations

import hashlib
import os
import urllib.request
from pathlib import Path

import pytest

from ceres.analyzers.model.gguf_static import inspect_gguf
from ceres.analyzers.model.onnx_static import inspect_onnx
from ceres.config import Policy
from ceres.runner import run_scan


REAL_FIXTURES_ENV = "CERES_RUN_REAL_MODEL_FIXTURES"
TORCH_FIXTURE_ENV = "CERES_RUN_TORCH_FIXTURE"

ONNX_ADD_URL = (
    "https://raw.githubusercontent.com/onnx/onnx/main/"
    "onnx/backend/test/data/node/test_add/model.onnx"
)
ONNX_ADD_SHA256 = "93cf0438706cddabf683adc8b13c8a17c4b8b12d8bccb1b041268e1f4dff0a2d"

GGUF_TINY_LLAMA_URL = "https://huggingface.co/Mozilla/llama-test-model/resolve/main/tiny-llama.gguf"
GGUF_TINY_LLAMA_SHA256 = "bbe1bd9e2d3671b980f32c70820f2cecd03c6d45dacff6f88a23a39da2d904c1"


def _policy() -> Policy:
    pol = Policy()
    pol.model_policy.require_known_source = False
    pol.dependency_policy.run_pip_audit = False
    pol.dependency_policy.run_gitleaks = False
    return pol


def _download(url: str, path: Path, expected_sha256: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read()
    actual_sha256 = hashlib.sha256(data).hexdigest()
    assert actual_sha256 == expected_sha256
    path.write_bytes(data)
    return path


def test_real_onnx_fixture_from_upstream(tmp_path):
    if os.environ.get(REAL_FIXTURES_ENV) != "1":
        pytest.skip(f"set {REAL_FIXTURES_ENV}=1 to download pinned real model fixtures")

    model = _download(ONNX_ADD_URL, tmp_path / "model.onnx", ONNX_ADD_SHA256)
    result = inspect_onnx(model)
    assert result.ok, result.error
    assert result.info is not None
    assert result.info.ir_version == 7
    assert result.info.producer_name == "backend-test"
    assert result.info.graph_name == "test_add"
    assert result.info.opset_imports == {"": 14}
    assert result.info.node_op_counts == {"Add": 1}


def test_real_gguf_fixture_from_upstream(tmp_path):
    if os.environ.get(REAL_FIXTURES_ENV) != "1":
        pytest.skip(f"set {REAL_FIXTURES_ENV}=1 to download pinned real model fixtures")

    model = _download(GGUF_TINY_LLAMA_URL, tmp_path / "tiny-llama.gguf", GGUF_TINY_LLAMA_SHA256)
    result = inspect_gguf(model)
    assert result.ok, result.error
    assert result.info is not None
    assert result.info.version == 3
    assert result.info.tensor_count == 12
    assert result.info.metadata_kv_count == 26
    assert result.info.metadata["general.architecture"] == "llama"


def test_real_torch_save_checkpoint_when_torch_is_available(tmp_path):
    if os.environ.get(TORCH_FIXTURE_ENV) != "1":
        pytest.skip(f"set {TORCH_FIXTURE_ENV}=1 to generate a real torch.save checkpoint")
    torch = pytest.importorskip("torch")

    repo = tmp_path / "repo"
    model = repo / "models" / "checkpoint.pt"
    model.parent.mkdir(parents=True)
    torch.save({"weight": torch.tensor([1.0, 2.0])}, model)

    findings, _suppressed, _counts, _passed, _inv = run_scan(
        repo,
        _policy(),
        None,
        repo / "ai-bom.json",
    )
    rule_ids = {finding.rule_id for finding in findings}
    assert "ceres.model.artifact.format_not_allowed" in rule_ids
    assert "ceres.model.artifact.prefer_safetensors" in rule_ids
    assert "ceres.model.artifact.pickle_opcode_risk" not in rule_ids
