from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ceres.findings.model import Finding, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(findings: list[Finding], counts: dict[str, int], passed: bool, console: Console | None = None) -> None:
    console = console or Console()
    if not findings:
        console.print("[green]Ceres scan: no findings.[/green]")
    else:
        table = Table(title="Ceres AI Security Scan", show_lines=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule")
        table.add_column("Location")
        table.add_column("Message")
        ordered = sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.file))
        for f in ordered:
            loc = f.file + (f":{f.line}" if f.line else "")
            style = _SEV_STYLE.get(f.severity, "")
            table.add_row(
                f"[{style}]{f.severity.value.upper()}[/{style}]",
                f.rule_id,
                loc,
                f.message,
            )
        console.print(table)

    bits = [f"{counts.get(s.value, 0)} {s.value}" for s in Severity if counts.get(s.value, 0)]
    if bits:
        console.print("Counts: " + ", ".join(bits))

    status = "[green]PASSED[/green]" if passed else "[red]FAILED[/red]"
    console.print(f"Scan result: {status}")
