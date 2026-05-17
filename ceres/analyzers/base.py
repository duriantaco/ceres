from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ceres.config import Policy
from ceres.findings.model import Finding
from ceres.inventory.walker import Inventory


@dataclass
class AnalyzerContext:
    root: Path
    inventory: Inventory
    policy: Policy
    baseline: dict | None = None

    def rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root))
        except ValueError:
            return str(p)


class Analyzer(Protocol):
    name: str

    def run(self, ctx: AnalyzerContext) -> list[Finding]: ...
