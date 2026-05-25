from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ceres.findings.model import Finding, Layer, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_PRIORITY_LIMIT = 8


def render(
    findings: list[Finding],
    counts: dict[str, int],
    passed: bool,
    console: Console | None = None,
    severity_gate: Mapping[str, str] | None = None,
) -> None:
    console = console or Console()
    if not findings:
        console.print(
            Panel(
                "[bold green]No findings.[/bold green]\n"
                "Ceres did not find AI security issues covered by the enabled policy.\n\n"
                "[bold]Next:[/bold] keep baselines and AI-BOMs current with "
                "`ceres baseline .` and `ceres bom . --out ai-bom.json`.",
                title="Ceres AI Security Scan",
                border_style="green",
            )
        )
    else:
        ordered = sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.file))
        failing = _failing_findings(ordered, severity_gate)
        console.print(_summary_panel(findings, failing, counts, passed))
        console.print(_layer_table(findings))
        console.print(_priority_table(ordered[:_PRIORITY_LIMIT], len(ordered)))
        if len(ordered) > _PRIORITY_LIMIT:
            console.print(_compact_table(ordered[_PRIORITY_LIMIT:]))
        console.print(_next_steps(passed, failing))

    bits = [f"{counts.get(s.value, 0)} {s.value}" for s in Severity if counts.get(s.value, 0)]
    if bits:
        console.print("[dim]Counts: " + ", ".join(bits) + "[/dim]")

    status = "[green]PASSED[/green]" if passed else "[red]FAILED[/red]"
    console.print(f"Scan result: {status}")


def _summary_panel(
    findings: list[Finding],
    failing: list[Finding],
    counts: dict[str, int],
    passed: bool,
) -> Panel:
    status = "[bold green]PASSED[/bold green]" if passed else "[bold red]FAILED[/bold red]"
    total = len(findings)
    fail_line = (
        f"{len(failing)} finding(s) reached a fail gate."
        if failing
        else "No finding reached a fail gate."
    )
    severity_bits = [f"{counts.get(s.value, 0)} {s.value}" for s in Severity if counts.get(s.value, 0)]
    text = (
        f"{status}\n"
        f"Ceres found [bold]{total}[/bold] finding(s). {escape(fail_line)}\n"
        f"Severity mix: {escape(', '.join(severity_bits) if severity_bits else 'none')}"
    )
    return Panel(text, title="Ceres AI Security Scan", border_style="green" if passed else "red")


def _layer_table(findings: list[Finding]) -> Table:
    by_layer = Counter(f.layer for f in findings)
    table = Table(title="Risk Areas", show_header=True, show_lines=False)
    table.add_column("Layer", no_wrap=True)
    table.add_column("Findings", justify="right")
    table.add_column("What this area means")
    for layer, count in sorted(by_layer.items(), key=lambda item: (-item[1], item[0].value)):
        table.add_row(
            layer.value,
            str(count),
            _layer_description(layer),
        )
    return table


def _priority_table(findings: list[Finding], total: int) -> Table:
    shown = len(findings)
    table = Table(title=f"What Ceres Caught First ({shown} of {total})", show_lines=True, expand=True)
    table.add_column("Finding", width=22, overflow="fold")
    table.add_column("Explanation", ratio=2, overflow="fold")
    for finding in findings:
        style = _SEV_STYLE.get(finding.severity, "")
        location = _location(finding)
        left = (
            f"[{style}]{finding.severity.value.upper()}[/{style}]\n"
            f"[bold]{escape(location)}[/bold]\n"
            f"[dim]{escape(finding.layer.value)}[/dim]"
        )
        right = (
            f"[bold]Rule:[/bold] {escape(finding.rule_id)}\n"
            f"[bold]Problem:[/bold] {escape(finding.message)}\n"
            f"[bold]Why it matters:[/bold] {escape(_why_it_matters(finding))}\n"
            f"[bold]Next step:[/bold] {escape(finding.recommendation)}"
        )
        evidence = _evidence_text(finding)
        if evidence:
            right += f"\n[bold]Evidence:[/bold] {evidence}"
        table.add_row(left, right)
    return table


def _compact_table(findings: list[Finding]) -> Table:
    table = Table(title=f"Additional Findings ({len(findings)})", show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Location", max_width=28, no_wrap=True, overflow="ellipsis")
    table.add_column("Details", ratio=2, overflow="fold")
    for finding in findings:
        style = _SEV_STYLE.get(finding.severity, "")
        details = (
            f"[dim]{escape(finding.rule_id)}[/dim]\n"
            f"[bold]Problem:[/bold] {escape(finding.message)}\n"
            f"[bold]Next:[/bold] {escape(finding.recommendation)}"
        )
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/{style}]",
            escape(_location(finding)),
            details,
        )
    return table


def _next_steps(passed: bool, failing: list[Finding]) -> Panel:
    if passed:
        body = (
            "[bold]Next:[/bold] review any warnings, update baselines after intentional model/data changes, "
            "and publish SARIF in CI with `ceres scan . --sarif-out ceres.sarif`."
        )
        return Panel(body, title="What To Do Next", border_style="green")

    severities = sorted({f.severity.value for f in failing}, key=lambda sev: Severity(sev).rank, reverse=True)
    sev_text = ", ".join(severities) if severities else "gated"
    body = (
        f"[bold]1.[/bold] Fix or explicitly waive the {escape(sev_text)} finding(s) above.\n"
        "[bold]2.[/bold] If the change is intentional, update provenance, dataset hashes, baselines, or policy in the same PR.\n"
        "[bold]3.[/bold] Rerun `ceres scan .`. For machine-readable review, add `--json-out ceres-report.json --sarif-out ceres.sarif`."
    )
    return Panel(body, title="What To Do Next", border_style="red")


def _failing_findings(findings: list[Finding], severity_gate: Mapping[str, str] | None) -> list[Finding]:
    gate = severity_gate or {"critical": "fail", "high": "fail"}
    return [f for f in findings if gate.get(f.severity.value) == "fail"]


def _location(finding: Finding) -> str:
    return finding.file + (f":{finding.line}" if finding.line else "")


def _evidence_text(finding: Finding) -> str:
    parts: list[str] = []
    if finding.evidence.matched_text_preview:
        parts.append(f"matched `{escape(_short(finding.evidence.matched_text_preview))}`")
    if finding.evidence.source:
        parts.append(f"source `{escape(_short(finding.evidence.source))}`")
    extras = [_format_extra(key, value) for key, value in list(finding.evidence.extra.items())[:3]]
    extras = [extra for extra in extras if extra]
    if extras:
        parts.append(escape(", ".join(extras)))
    return "; ".join(parts)


def _format_extra(key: str, value: object) -> str | None:
    if value in (None, "", [], {}):
        return None
    text = _short(value)
    lowered = key.lower()
    if ("sha" in lowered or "hash" in lowered) and len(text) >= 32:
        text = text[:12] + "..."
    return f"{key}={text!r}"


def _short(value: object, limit: int = 72) -> str:
    text = str(value).replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _layer_description(layer: Layer) -> str:
    descriptions = {
        Layer.CODE: "AI-relevant code patterns such as unsafe loaders, dynamic execution, or prompt plumbing.",
        Layer.MODEL: "Model artifacts, model references, tensors, tokenizers, adapters, and provenance.",
        Layer.DATA: "Training/eval dataset provenance, hashes, duplication, labels, and poisoning indicators.",
        Layer.EVAL: "Safety evals, regression gates, generation settings, guardrails, and filters.",
        Layer.RAG: "Retrieval corpus content, indexing, permission filters, citations, and indirect injection.",
        Layer.PROMPT: "Prompt templates and system-context boundaries.",
        Layer.AGENT: "Agent tools, MCP/tool metadata, permissions, and approval gates.",
        Layer.DEPS: "Dependency, CI, Docker, and external scanner supply-chain signals.",
        Layer.BOM: "AI-BOM coverage and traceability gaps.",
        Layer.POLICY: "Waivers, policy issues, and scanner completeness.",
    }
    return descriptions[layer]


def _why_it_matters(finding: Finding) -> str:
    rule = finding.rule_id
    checks = (
        ("remote_code_enabled", "Remote model code can execute during load, turning a model reference into code execution."),
        ("revision_unpinned", "The referenced model can change without review, which weakens reproducibility and provenance."),
        ("torch_unsafe_load", "PyTorch checkpoints can contain pickle payloads, so unsafe loading can execute code."),
        ("pickle", "Pickle-backed model loading can execute arbitrary code from an artifact."),
        ("source_missing_or_unapproved", "Missing or unapproved model provenance makes it harder to verify where the artifact came from."),
        ("lora", "Adapters can alter model behavior while leaving the base model looking unchanged."),
        ("tokenizer", "Tokenizer and chat-template changes can hide behavior changes outside model weights."),
        ("tensor", "Unexpected tensor drift can indicate swapped weights, adapter merges, or incompatible artifacts."),
        ("dataset.hash", "A dataset hash mismatch means training data changed outside the declared manifest."),
        ("dataset.manifest", "Missing or stale manifests remove the audit trail needed to review training data changes."),
        ("dataset.source", "Unapproved sources increase poisoning and compliance risk."),
        ("dataset.duplicate", "Duplicate floods can overweight poisoned or low-quality examples."),
        ("dataset.label", "Label drift can silently change what the model learns."),
        ("dataset.rare_phrase", "Repeated rare phrases can act as backdoor trigger indicators."),
        ("rag.index", "Unreviewed user documents can poison the retrieval index before the model sees them."),
        ("rag.retrieval.filter_missing", "Missing retrieval filters can expose private or cross-tenant documents."),
        ("rag.retrieval.permission_after_retrieval", "Checking permissions after retrieval can leak unauthorized context."),
        ("rag.citations_disabled", "Without citations, users and reviewers lose grounding for retrieved answers."),
        ("rag.instruction", "Retrieved text can become an indirect prompt injection payload."),
        ("rag.hidden", "Hidden markup can smuggle instructions into a RAG corpus."),
        ("rag.encoded", "Encoded blobs can hide instructions or payloads from normal review."),
        ("agent.tool.shell_without_allowlist", "A model-controlled shell tool creates a large blast radius without command constraints."),
        ("agent.tool.risky_tool_without_approval", "High-impact tools need approval gates so the model cannot act unilaterally."),
        ("agent.tool.description", "Tool metadata is model-visible context and can be poisoned to steer agent behavior."),
        ("agent.tool.sensitive", "Tool descriptions requesting secrets can turn normal tool use into exfiltration."),
        ("eval.", "Weak or skipped eval gates can let unsafe model, prompt, adapter, or RAG changes ship."),
        ("prompt.system_context_user_slot", "Putting user input into system context weakens instruction boundaries."),
        ("dynamic_execution", "Dynamic execution lets input or generated strings become executable code."),
        ("supplychain.remote_script_pipe", "Piping remote scripts into interpreters executes unaudited code during setup or CI."),
        ("supplychain.git_dependency_unpinned", "Unpinned git dependencies can change without version review."),
        ("supplychain.docker_image_unpinned", "Unpinned images can change underneath the same tag."),
        ("supplychain.lockfile_missing", "Without a lockfile, CI may resolve a different dependency graph each run."),
        ("supplychain.vulnerable_dependency", "Known vulnerable dependencies can be exploited through the AI app stack."),
        ("aibom.coverage_missing", "Missing AI-BOM coverage weakens incident response and artifact traceability."),
        ("policy.waiver_expired", "Expired waivers hide risk decisions that need re-approval."),
        ("engine.analyzer_failed", "A failed analyzer means the scan is incomplete and should not be treated as clean."),
    )
    for fragment, explanation in checks:
        if fragment in rule:
            return explanation
    return "This finding marks an AI-specific control gap that should be reviewed before deployment."
