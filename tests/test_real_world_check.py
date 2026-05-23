from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "real_world_check.py"


def _load_harness():
    spec = importlib.util.spec_from_file_location("real_world_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_real_world_harness_detects_seeded_ai_risks(tmp_path):
    harness = _load_harness()
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text("def ok():\n    return 'clean'\n")

    result = harness.run_validation(
        [str(repo)],
        scenario_names=[
            "hf_trust_remote_code",
            "agent_shell_tool",
            "rag_prompt_injection",
            "lora_base_drift",
            "safetensors_tensor_drift",
        ],
        workdir=tmp_path / "work",
        keep_workdir=True,
    )

    assert result["summary"]["failed"] == 0
    scenarios = result["repos"][0]["scenarios"]
    assert {scenario["name"] for scenario in scenarios} == {
        "hf_trust_remote_code",
        "agent_shell_tool",
        "rag_prompt_injection",
        "lora_base_drift",
        "safetensors_tensor_drift",
    }
    for scenario in scenarios:
        assert scenario["passed"] is True
        assert scenario["matched_expected"] == scenario["expected"]
        assert scenario["missed"] == []
        assert scenario["injected_findings"]


def test_real_world_harness_rejects_unknown_scenario():
    harness = _load_harness()
    try:
        harness.run_validation(["."], scenario_names=["nope"])
    except SystemExit as exc:
        assert "unknown scenario" in str(exc)
    else:
        raise AssertionError("unknown scenario should raise SystemExit")


def test_real_world_harness_combined_mode(tmp_path):
    harness = _load_harness()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("clean repo\n")

    result = harness.run_validation(
        [str(repo)],
        scenario_names=["hf_trust_remote_code", "unsafe_torch_load"],
        combined=True,
        workdir=tmp_path / "work-combined",
        keep_workdir=True,
    )

    assert result["summary"]["mode"] == "combined"
    assert result["summary"]["failed"] == 0
    scenarios = {scenario["name"]: scenario for scenario in result["repos"][0]["scenarios"]}
    assert scenarios["hf_trust_remote_code"]["passed"] is True
    assert scenarios["unsafe_torch_load"]["passed"] is True
    assert scenarios["hf_trust_remote_code"]["matched_expected"] == scenarios["hf_trust_remote_code"]["expected"]
    assert scenarios["unsafe_torch_load"]["matched_expected"] == scenarios["unsafe_torch_load"]["expected"]


def test_real_world_harness_loads_corpus_file(tmp_path):
    harness = _load_harness()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("clean repo\n")
    corpus = tmp_path / "corpus.yml"
    corpus.write_text(
        "repos:\n"
        "  - repo\n"
        "scenarios:\n"
        "  - hf_trust_remote_code\n"
    )

    corpus_config = harness._load_corpus(corpus)
    assert corpus_config.sources == [str(repo.resolve())]
    assert corpus_config.scenarios == ["hf_trust_remote_code"]

    result = harness.run_validation(
        corpus_config.sources,
        scenario_names=corpus_config.scenarios,
        combined=True,
        workdir=tmp_path / "work-corpus",
        keep_workdir=True,
    )

    assert result["summary"]["failed"] == 0
    assert result["summary"]["scenarios"] == 1
    assert result["repos"][0]["scenarios"][0]["name"] == "hf_trust_remote_code"


def test_real_world_harness_enforces_clean_budgets(tmp_path):
    harness = _load_harness()
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text("def run(code):\n    return eval(code)\n")
    policy = tmp_path / "ceres.yml"
    policy.write_text(
        "real_world_validation:\n"
        "  clean_budgets:\n"
        "    high: 0\n"
    )

    result = harness.run_validation(
        [str(repo)],
        scenario_names=["hf_trust_remote_code"],
        combined=True,
        workdir=tmp_path / "work-budget",
        keep_workdir=True,
        policy_path=policy,
    )

    assert result["summary"]["failed_scenarios"] == 0
    assert result["summary"]["budget_failures"] == 1
    assert result["summary"]["failed"] == 1
    assert result["repos"][0]["clean_budget_violations"]
