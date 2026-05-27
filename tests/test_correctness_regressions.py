from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ceres.analyzers.model.pickle_static import scan_pickle_bytes
from ceres.cli import app
from ceres.config import Policy, PolicyError
from ceres.gitdiff import collect_git_diff
from ceres.runner import run_scan


CLI = CliRunner()


def _rule_ids(findings):
    return {finding.rule_id for finding in findings}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_pickle_global_matching_does_not_substring_match_benign_modules():
    result = scan_pickle_bytes(b"cagent\nRunner\n.")
    assert result.error is None
    assert result.suspicious_globals == []
    assert result.is_dangerous is False

    dangerous = scan_pickle_bytes(b"cos\nsystem\n.")
    assert dangerous.suspicious_globals == ["os.system"]
    assert dangerous.is_dangerous is True


def test_cli_explicit_missing_policy_fails(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    result = CLI.invoke(app, ["scan", str(repo), "--policy", "security/ceres.yml"])

    assert result.exit_code == 2
    assert "Policy file not found" in result.output


def test_unknown_policy_keys_are_rejected(tmp_path):
    policy = tmp_path / "ceres.yml"
    policy.write_text("model_policy:\n  require_sha256_TYPO: false\n")

    with pytest.raises(PolicyError, match="require_sha256_TYPO"):
        Policy.load(policy)

    repo = tmp_path / "repo"
    repo.mkdir()
    result = CLI.invoke(app, ["scan", str(repo), "--policy", str(policy)])
    assert result.exit_code == 2
    assert "Policy error" in result.output
    assert "require_sha256_TYPO" in result.output


def test_malformed_waiver_becomes_policy_finding(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    pol = Policy()
    pol.waivers = [{"file": "src/app.py"}]

    findings, _suppressed, counts, passed, _inv = run_scan(repo, pol, None, None)
    assert "ceres.policy.waiver_invalid" in _rule_ids(findings)
    assert counts["high"] == 1
    assert passed is False


def test_diff_untracked_large_binary_does_not_read_lines(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "README.md").write_text("base\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")

    model = repo / "models" / "new.safetensors"
    model.parent.mkdir()
    model.write_bytes(b"\x00" * (1024 * 1024 + 1))

    diff = collect_git_diff(repo, "HEAD")
    assert "models/new.safetensors" in diff.changed_files
    assert "models/new.safetensors" not in diff.changed_lines


def test_model_hash_is_not_computed_without_baseline(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.gguf"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"GGUF")

    from ceres.analyzers.model import scanner

    def boom(_path: Path) -> str:
        raise AssertionError("hash should not be computed without baseline")

    monkeypatch.setattr(scanner, "_sha256_file", boom)
    pol = Policy()
    pol.model_policy.require_known_source = False
    pol.dependency_policy.run_pip_audit = False

    findings, _suppressed, _counts, _passed, _inv = run_scan(repo, pol, None, repo / "ai-bom.json")
    assert "ceres.model.gguf.header_invalid" in _rule_ids(findings)


def test_source_allowlist_requires_segment_boundary(tmp_path):
    repo = tmp_path / "repo"
    model = repo / "models" / "model.onnx"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"\x08\x07B\x04\x0a\x00\x10\x0e")
    (repo / "models" / "model.json").write_text(json.dumps({"source": "microsoft-evil/model"}))

    pol = Policy()
    pol.model_policy.approved_model_sources = ["huggingface.co/microsoft"]
    pol.dependency_policy.run_pip_audit = False

    findings, _suppressed, _counts, _passed, _inv = run_scan(repo, pol, None, repo / "ai-bom.json")
    assert "ceres.model.artifact.source_missing_or_unapproved" in _rule_ids(findings)


def test_root_temperature_without_ai_context_is_not_flagged(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.yaml").write_text("temperature: 1.4\n")

    findings, _suppressed, _counts, _passed, _inv = run_scan(repo, Policy(), None, None)
    assert "ceres.eval.generation_temperature_high" not in _rule_ids(findings)

    cfg = repo / "eval.yaml"
    cfg.write_text("temperature: 1.4\n")
    findings, _suppressed, _counts, _passed, _inv = run_scan(repo, Policy(), None, None)
    assert "ceres.eval.generation_temperature_high" in _rule_ids(findings)
