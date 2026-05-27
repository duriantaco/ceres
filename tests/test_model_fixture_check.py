from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "model_fixture_check.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("model_fixture_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_model_fixture_corpus_loads():
    script = _load_script()
    fixtures = script._load_corpus(REPO_ROOT / "examples" / "model-fixture-corpus.yml")
    by_name = {fixture.name: fixture for fixture in fixtures}

    assert set(by_name) == {"onnx-backend-test-add", "mozilla-tiny-llama-gguf"}
    assert by_name["onnx-backend-test-add"].kind == "onnx"
    assert by_name["mozilla-tiny-llama-gguf"].kind == "gguf"
    assert by_name["onnx-backend-test-add"].sha256
    assert by_name["mozilla-tiny-llama-gguf"].corruptions[0]["expected_rule"]


def test_model_fixture_expected_comparison_reports_nested_mismatches():
    script = _load_script()
    failures = script._compare_expected(
        {
            "ir_version": 7,
            "opset_imports": {"": 14},
            "node_op_counts": {"Add": 1},
        },
        {
            "ir_version": 8,
            "opset_imports": {"": 14},
            "node_op_counts": {"Mul": 1},
        },
    )

    assert "ir_version: expected 7, got 8" in failures
    assert "node_op_counts.Add: expected 1, got None" in failures
