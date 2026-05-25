from __future__ import annotations

import json
from pathlib import Path

from ceres.findings.model import Finding


def write_json(
    findings: list[Finding],
    out: Path,
    *,
    passed: bool,
    counts: dict[str, int],
    metadata: dict | None = None,
) -> Path:
    payload = {
        "passed": passed,
        "counts": counts,
        "findings": [f.to_dict() for f in findings],
    }
    if metadata:
        payload["metadata"] = metadata
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    return out
