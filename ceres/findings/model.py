from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Layer(str, Enum):
    CODE = "code"
    MODEL = "model"
    DATA = "data"
    EVAL = "eval"
    RAG = "rag"
    PROMPT = "prompt"
    AGENT = "agent"
    DEPS = "deps"
    BOM = "bom"
    POLICY = "policy"


@dataclass(frozen=True)
class FrameworkMap:
    owasp_llm: tuple[str, ...] = ()
    owasp_ml: tuple[str, ...] = ()
    mitre_atlas: tuple[str, ...] = ()
    nist_aml: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        if self.owasp_llm:
            out["owasp_llm"] = list(self.owasp_llm)
        if self.owasp_ml:
            out["owasp_ml"] = list(self.owasp_ml)
        if self.mitre_atlas:
            out["mitre_atlas"] = list(self.mitre_atlas)
        if self.nist_aml:
            out["nist_aml"] = list(self.nist_aml)
        return out


@dataclass
class Evidence:
    matched_text_preview: str | None = None
    source: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.matched_text_preview is not None:
            out["matched_text_preview"] = self.matched_text_preview
        if self.source is not None:
            out["source"] = self.source
        out.update(self.extra)
        return out


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    layer: Layer
    file: str
    message: str
    recommendation: str
    line: int | None = None
    column: int | None = None
    evidence: Evidence = field(default_factory=Evidence)
    frameworks: FrameworkMap = field(default_factory=FrameworkMap)
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "layer": self.layer.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence.to_dict(),
            "frameworks": self.frameworks.to_dict(),
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }
