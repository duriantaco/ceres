from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from ceres import __version__
from ceres.analyzers.bom.aibom import write_bom
from ceres.baseline.store import build_baseline, save_baseline
from ceres.config import DEFAULT_POLICY_YAML, Policy
from ceres.inventory.walker import build_inventory
from ceres.reporters.cli import render as render_cli
from ceres.reporters.json_reporter import write_json
from ceres.reporters.sarif import write_sarif
from ceres.runner import run_scan

app = typer.Typer(
    add_completion=False,
    help="Ceres — developer-first AI security scanner for AI/ML repos.",
)
console = Console()


def _repo_root(path: Path) -> Path:
    return path.expanduser().resolve()


def _under_root(root: Path, path: Path | None) -> Path | None:
    if path is None:
        return None
    if path.is_absolute():
        return path
    return root / path


def _version(value: bool):
    if value:
        console.print(f"ceres {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version, is_eager=True, help="Print version and exit."
    ),
) -> None:
    pass


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Repository root"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing ceres.yml"),
) -> None:
    root = _repo_root(path)
    out = root / "ceres.yml"
    if out.exists() and not force:
        console.print(f"[yellow]{out} already exists. Use --force to overwrite.[/yellow]")
        raise typer.Exit(1)
    out.write_text(DEFAULT_POLICY_YAML)
    console.print(f"[green]Wrote {out}[/green]")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Repository root"),
    policy_path: Path = typer.Option(
        Path("ceres.yml"), "--policy", "-p", help="Policy file (ceres.yml)"
    ),
    baseline: Optional[Path] = typer.Option(
        None, "--baseline", help="Baseline file (default: .ceres/baseline.json if present)"
    ),
    bom: Optional[Path] = typer.Option(
        Path("ai-bom.json"), "--bom", help="AI-BOM JSON path (existence is checked, not contents)"
    ),
    json_out: Optional[Path] = typer.Option(None, "--json-out", help="Write JSON report to this path"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif-out", help="Write SARIF report to this path"),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on", help="Override gate: comma list of severities to fail on (critical,high,medium,low)"
    ),
) -> None:
    root = _repo_root(path)
    resolved_policy = _under_root(root, policy_path)
    policy = Policy.load(resolved_policy if resolved_policy and resolved_policy.exists() else None)

    if fail_on:
        gates = policy.severity_gate.as_dict()
        targets = {s.strip().lower() for s in fail_on.split(",") if s.strip()}
        for sev in gates:
            gates[sev] = "fail" if sev in targets else "info"
        policy.severity_gate = type(policy.severity_gate)(**gates)

    if baseline is None:
        default_baseline = root / ".ceres" / "baseline.json"
        baseline = default_baseline if default_baseline.exists() else None
    else:
        baseline = _under_root(root, baseline)

    bom = _under_root(root, bom)

    findings, suppressed, counts, passed, _inv = run_scan(root, policy, baseline, bom)
    render_cli(findings, counts, passed, console=console)
    if suppressed:
        console.print(f"[dim]({len(suppressed)} finding(s) suppressed by waivers)[/dim]")

    if json_out:
        write_json(findings, json_out, passed=passed, counts=counts)
        console.print(f"[dim]Wrote JSON report to {json_out}[/dim]")
    if sarif_out:
        write_sarif(findings, sarif_out)
        console.print(f"[dim]Wrote SARIF report to {sarif_out}[/dim]")

    raise typer.Exit(0 if passed else 1)


@app.command()
def baseline(
    path: Path = typer.Argument(Path("."), help="Repository root"),
    out: Path = typer.Option(Path(".ceres/baseline.json"), "--out", help="Baseline output path"),
) -> None:
    root = _repo_root(path)
    out = _under_root(root, out) or out
    inv = build_inventory(root)
    b = build_baseline(inv)
    save_baseline(b, out)
    console.print(f"[green]Wrote baseline to {out}[/green]")
    console.print(f"Models: {len(b['models'])}, Datasets: {len(b['datasets'])}, Tools: {len(b.get('tools', {}))}")


@app.command()
def bom(
    path: Path = typer.Argument(Path("."), help="Repository root"),
    out: Path = typer.Option(Path("ai-bom.json"), "--out", help="AI-BOM output path"),
) -> None:
    root = _repo_root(path)
    out = _under_root(root, out) or out
    inv = build_inventory(root)
    write_bom(inv, out)
    console.print(f"[green]Wrote AI-BOM to {out}[/green]")


@app.command(name="list-rules")
def list_rules() -> None:
    rules = sorted(
        {
            "ceres.ai_code.dynamic_execution",
            "ceres.model.loader.pickle_deserialize",
            "ceres.model.loader.joblib_deserialize",
            "ceres.model.loader.torch_unsafe_load",
            "ceres.model.loader.remote_code_enabled",
            "ceres.model.loader.revision_unpinned",
            "ceres.agent.tool.shell_without_allowlist",
            "ceres.agent.tool.risky_tool_without_approval",
            "ceres.agent.tool.description_prompt_injection",
            "ceres.agent.tool.sensitive_context_request",
            "ceres.agent.tool.cross_tool_instruction",
            "ceres.agent.tool.hidden_instruction_markup",
            "ceres.agent.tool.description_drift",
            "ceres.agent.tool.added",
            "ceres.agent.tool.removed",
            "ceres.prompt.secret_literal",
            "ceres.prompt.system_context_user_slot",
            "ceres.model.config.revision_unpinned",
            "ceres.model.artifact.pickle_format",
            "ceres.model.artifact.format_not_allowed",
            "ceres.model.artifact.prefer_safetensors",
            "ceres.model.artifact.source_missing_or_unapproved",
            "ceres.model.artifact.pickle_opcode_risk",
            "ceres.model.safetensors.header_invalid",
            "ceres.model.safetensors.header_oversized",
            "ceres.model.tensor.added",
            "ceres.model.tensor.removed",
            "ceres.model.tensor.shape_changed",
            "ceres.model.tensor.dtype_changed",
            "ceres.model.tensor.hash_drift",
            "ceres.model.tensor.nan_or_inf",
            "ceres.model.tensor.norm_drift",
            "ceres.model.tensor.range_anomaly",
            "ceres.model.tensor.sparsity_drift",
            "ceres.model.tensor.suspicious_name",
            "ceres.model.artifact.hash_drift",
            "ceres.model.tokenizer.special_token_drift",
            "ceres.model.chat_template.drift",
            "ceres.model.lora.base_model_drift",
            "ceres.dataset.manifest_missing",
            "ceres.dataset.manifest_incomplete",
            "ceres.dataset.manifest_stale_hash",
            "ceres.dataset.hash_missing",
            "ceres.dataset.hash_drift",
            "ceres.dataset.source_unapproved",
            "ceres.dataset.duplicate_flood",
            "ceres.dataset.label_distribution_drift",
            "ceres.dataset.rare_phrase_repetition",
            "ceres.rag.instruction.ignore_context",
            "ceres.rag.instruction.system_override",
            "ceres.rag.instruction.secret_request",
            "ceres.rag.instruction.tool_request",
            "ceres.rag.instruction.exfiltration",
            "ceres.rag.index.user_docs_without_sanitizer",
            "ceres.rag.retrieval.filter_missing",
            "ceres.rag.retrieval.permission_after_retrieval",
            "ceres.rag.citations_disabled",
            "ceres.rag.source_metadata_missing",
            "ceres.rag.owner_missing",
            "ceres.rag.domain_unapproved",
            "ceres.rag.hidden_instruction_markup",
            "ceres.rag.encoded_payload",
            "ceres.rag.invisible_control_chars",
            "ceres.supplychain.vulnerable_dependency",
            "ceres.supplychain.scanner_unavailable",
            "ceres.supplychain.dependency_unpinned",
            "ceres.supplychain.lockfile_missing",
            "ceres.supplychain.remote_script_pipe",
            "ceres.supplychain.git_dependency_unpinned",
            "ceres.supplychain.docker_image_unpinned",
            "ceres.supplychain.secret_scanner_hit.*",
            "ceres.eval.safety_eval_disabled",
            "ceres.eval.regression_gate_disabled",
            "ceres.eval.safety_filter_disabled",
            "ceres.eval.safety_threshold_low",
            "ceres.eval.generation_temperature_high",
            "ceres.aibom.coverage_missing",
            "ceres.policy.waiver_expired",
            "ceres.engine.analyzer_failed",
        }
    )
    for r in rules:
        console.print(r)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
