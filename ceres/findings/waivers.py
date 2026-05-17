from __future__ import annotations

import datetime as _dt
import fnmatch
from dataclasses import dataclass

from ceres.findings.model import Finding


@dataclass
class Waiver:
    rule_id: str
    file: str | None = None
    reason: str = ""
    expires: _dt.date | None = None
    approved_by: str | None = None

    def matches(self, finding: Finding) -> bool:
        if finding.rule_id != self.rule_id:
            return False
        if self.file and not fnmatch.fnmatch(finding.file, self.file):
            return False
        return True

    def is_expired(self, today: _dt.date | None = None) -> bool:
        if self.expires is None:
            return False
        today = today or _dt.date.today()
        return today > self.expires


def parse_waivers(raw: list[dict]) -> list[Waiver]:
    out: list[Waiver] = []
    for item in raw or []:
        expires = item.get("expires")
        if isinstance(expires, str):
            expires = _dt.date.fromisoformat(expires)
        out.append(
            Waiver(
                rule_id=item["rule_id"],
                file=item.get("file"),
                reason=item.get("reason", ""),
                expires=expires,
                approved_by=item.get("approved_by"),
            )
        )
    return out


def apply_waivers(
    findings: list[Finding],
    waivers: list[Waiver],
    today: _dt.date | None = None,
) -> tuple[list[Finding], list[Finding], list[Waiver]]:

    today = today or _dt.date.today()
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    expired: list[Waiver] = []
    active: list[Waiver] = []

    for waiver in waivers:
        if waiver.is_expired(today):
            expired.append(waiver)
        else:
            active.append(waiver)

    for f in findings:
        matched = False
        for waiver in active:
            if waiver.matches(f):
                matched = True
                break
        if matched:
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed, expired
