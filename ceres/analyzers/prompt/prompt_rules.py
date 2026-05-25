from __future__ import annotations

import re

from ceres.analyzers.base import AnalyzerContext
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity

_USER_INPUT_RE = re.compile(r"\{(?:user_input|user|message|query|question)\}", re.IGNORECASE)
_API_KEY_RE = re.compile(
    r"(sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|pplx-[A-Za-z0-9]{20,})"
)


def run(ctx: AnalyzerContext) -> list[Finding]:
    findings: list[Finding] = []
    for path in ctx.inventory.prompts:
        rel = ctx.rel(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if _USER_INPUT_RE.search(text):
            findings.append(
                Finding(
                    rule_id="ceres.prompt.system_context_user_slot",
                    severity=Severity.MEDIUM,
                    layer=Layer.PROMPT,
                    file=rel,
                    message="Prompt template interpolates user input directly into the system context.",
                    recommendation="Move user input to a user-role turn, or escape/template it before concatenation.",
                    evidence=Evidence(matched_text_preview=_first_match(text, _USER_INPUT_RE)),
                    frameworks=FrameworkMap(owasp_llm=("LLM01",)),
                )
            )

        if ctx.policy.code_policy.scan_inline_secrets:
            for m in _API_KEY_RE.finditer(text):
                lineno = text.count("\n", 0, m.start()) + 1
                findings.append(
                    Finding(
                        rule_id="ceres.prompt.secret_literal",
                        severity=Severity.CRITICAL,
                        layer=Layer.PROMPT,
                        file=rel,
                        line=lineno,
                        message="Likely API key in prompt template.",
                        recommendation="Use Skylos for generic secret scanning; keep AI prompts free of inline credentials.",
                        evidence=Evidence(matched_text_preview=m.group(0)[:8] + "..."),
                        frameworks=FrameworkMap(owasp_llm=("LLM06",)),
                    )
                )

    return findings


def _first_match(text: str, pattern: re.Pattern) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    start = max(0, m.start() - 30)
    end = min(len(text), m.end() + 30)
    return text[start:end].strip()
