from __future__ import annotations

import json
from pathlib import Path

from ceres import __version__
from ceres.findings.model import Finding, Severity

_SEV_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def write_sarif(findings: list[Finding], out: Path) -> Path:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message[:120]},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {"level": _SEV_TO_LEVEL[f.severity]},
                "properties": {
                    "layer": f.layer.value,
                    "frameworks": f.frameworks.to_dict(),
                },
            },
        )
        loc: dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
            }
        }
        if f.line:
            loc["physicalLocation"]["region"] = {
                "startLine": f.line,
                **({"startColumn": f.column} if f.column else {}),
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SEV_TO_LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [loc],
                "properties": {
                    "severity": f.severity.value,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence.to_dict(),
                    "frameworks": f.frameworks.to_dict(),
                    "confidence": f.confidence,
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ceres",
                        "informationUri": "https://github.com/duriantaco/ceres",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif, indent=2))
    return out
