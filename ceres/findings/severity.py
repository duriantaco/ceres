from __future__ import annotations

from ceres.findings.model import Finding, Severity


def gate(findings: list[Finding], gates: dict[str, str]) -> tuple[bool, dict[str, int]]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    failed = False
    for sev, action in gates.items():
        if action == "fail" and counts.get(sev, 0) > 0:
            failed = True
            break
    return (not failed), counts
