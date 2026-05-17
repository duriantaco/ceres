from __future__ import annotations

import re
from dataclasses import dataclass

# Fuzzy patterns — each one needs only its words to appear within a small window.
@dataclass(frozen=True)
class Pattern:
    rule_id: str
    description: str
    keywords: tuple[str, ...]
    severity: str = "high"


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        "ceres.rag.instruction.ignore_context",
        "Instruction telling the model to ignore previous/prior instructions.",
        ("ignore", "previous", "instruction"),
    ),
    Pattern(
        "ceres.rag.instruction.ignore_context",
        "Instruction telling the model to disregard prior instructions.",
        ("disregard", "prior", "instruction"),
    ),
    Pattern(
        "ceres.rag.instruction.system_override",
        "Attempt to override the system prompt or developer message.",
        ("system", "prompt"),
        severity="high",
    ),
    Pattern(
        "ceres.rag.instruction.system_override",
        "Document declares a new role for the model.",
        ("you", "are", "now"),
        severity="medium",
    ),
    Pattern(
        "ceres.rag.instruction.secret_request",
        "Document instructs the model to reveal secrets/keys.",
        ("reveal", "secret"),
    ),
    Pattern(
        "ceres.rag.instruction.secret_request",
        "Document instructs the model to send/leak an API key.",
        ("send", "api", "key"),
    ),
    Pattern(
        "ceres.rag.instruction.tool_request",
        "Document tells the model to invoke a tool / call an action.",
        ("call", "tool"),
        severity="high",
    ),
    Pattern(
        "ceres.rag.instruction.tool_request",
        "Document tells the model to run a shell command.",
        ("run", "shell"),
    ),
    Pattern(
        "ceres.rag.instruction.tool_request",
        "Document tells the model to execute code.",
        ("execute", "code"),
    ),
    Pattern(
        "ceres.rag.instruction.exfiltration",
        "Document mentions exfiltration of data.",
        ("exfiltrate",),
    ),
)


_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_WINDOW = 8  # tokens


def find_injections(text: str) -> list[tuple[Pattern, int]]:
    hits: list[tuple[Pattern, int]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        toks = _TOKEN_RE.findall(line.lower())
        if not toks:
            continue
        for pattern in PATTERNS:
            if _window_contains(toks, pattern.keywords):
                hits.append((pattern, lineno))
    return hits


def _window_contains(toks: list[str], keywords: tuple[str, ...]) -> bool:
    indices = []
    for kw in keywords:
        idx = _find_token(toks, kw)
        if idx is None:
            return False
        indices.append(idx)
    return max(indices) - min(indices) <= _WINDOW


def _find_token(toks: list[str], keyword: str) -> int | None:
    for i, tok in enumerate(toks):
        if tok == keyword:
            return i
        if len(keyword) > 3 and tok.rstrip("s") == keyword:
            return i
    return None
