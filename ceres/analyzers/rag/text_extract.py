from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from ceres.analyzers.base import AnalyzerContext
from ceres.analyzers.rag.injection_patterns import Pattern, find_injections
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity

_HIDDEN_HTML_RE = re.compile(
    r"<[^>]+style=[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^\"']*[\"'][^>]*>",
    re.IGNORECASE,
)
_HTML_COMMENT_RE = re.compile(r"<!--(.+?)-->", re.DOTALL)
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{60,}={0,2})\b")
_LINK_RE = re.compile(r"https?://[^\s)>\"']+")
_INVISIBLE_RANGES = [
    (0x200B, 0x200F),  # zero-width / bidi marks
    (0x202A, 0x202E),  # bidi embed / override
    (0x2060, 0x2064),  # word joiner / invisible operators
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
]
_INVISIBLE_CHAR_RE = re.compile(
    "[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _INVISIBLE_RANGES) + "]"
)


def run(ctx: AnalyzerContext) -> list[Finding]:
    findings: list[Finding] = []
    pol = ctx.policy.rag_policy
    for path in ctx.inventory.rag_docs:
        if path.suffix.lower() == ".pdf":
            continue  # PDF extraction is out-of-scope for MVP
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = ctx.rel(path)
        findings.extend(_scan(text, rel, pol))
    return findings


def _scan(text: str, rel: str, pol) -> list[Finding]:
    out: list[Finding] = []
    metadata = _front_matter(text)

    if pol.require_source_metadata and not metadata.get("source"):
        out.append(
            Finding(
                rule_id="ceres.rag.source_metadata_missing",
                severity=Severity.MEDIUM,
                layer=Layer.RAG,
                file=rel,
                message="RAG document is missing source metadata.",
                recommendation="Add front-matter source metadata before indexing this document.",
                frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05")),
            )
        )

    if pol.require_doc_owner and not metadata.get("owner"):
        out.append(
            Finding(
                rule_id="ceres.rag.owner_missing",
                severity=Severity.MEDIUM,
                layer=Layer.RAG,
                file=rel,
                message="RAG document is missing owner metadata.",
                recommendation="Add an owner to the document front matter so risky content has accountability.",
                frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05")),
            )
        )

    if pol.allowed_domains:
        for url in _document_urls(text, metadata):
            host = urlparse(url).hostname or ""
            if host and not _domain_allowed(host, pol.allowed_domains):
                out.append(
                    Finding(
                        rule_id="ceres.rag.domain_unapproved",
                        severity=Severity.HIGH,
                        layer=Layer.RAG,
                        file=rel,
                        message=f"RAG document references unapproved domain '{host}'.",
                        recommendation="Use approved corpus sources or update rag_policy.allowed_domains after review.",
                        evidence=Evidence(matched_text_preview=url[:160]),
                        frameworks=FrameworkMap(owasp_llm=("LLM03", "LLM05")),
                    )
                )

    if pol.block_instruction_like_content:
        for pat, lineno in find_injections(text):
            out.append(_finding_from_pattern(pat, rel, lineno, _line(text, lineno)))

    if pol.scan_hidden_html:
        for m in _HIDDEN_HTML_RE.finditer(text):
            lineno = text.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    rule_id="ceres.rag.hidden_instruction_markup",
                    severity=Severity.HIGH,
                    layer=Layer.RAG,
                    file=rel,
                    line=lineno,
                    message="Document contains hidden HTML element (display:none / opacity:0 / etc.).",
                    recommendation="Strip hidden content from RAG inputs; it can carry covert instructions.",
                    evidence=Evidence(matched_text_preview=m.group(0)[:160]),
                    frameworks=FrameworkMap(owasp_llm=("LLM01",)),
                )
            )

        for m in _HTML_COMMENT_RE.finditer(text):
            inner = m.group(1).strip()
            if any(kw in inner.lower() for kw in ("ignore", "system prompt", "you are", "reveal", "tool", "exec")):
                lineno = text.count("\n", 0, m.start()) + 1
                out.append(
                    Finding(
                        rule_id="ceres.rag.hidden_instruction_markup",
                        severity=Severity.MEDIUM,
                        layer=Layer.RAG,
                        file=rel,
                        line=lineno,
                        message="HTML comment in RAG document contains instruction-like text.",
                        recommendation="Strip HTML comments before indexing, or treat the doc as untrusted.",
                        evidence=Evidence(matched_text_preview=inner[:160]),
                        frameworks=FrameworkMap(owasp_llm=("LLM01",)),
                    )
                )

    for m in _BASE64_RE.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        out.append(
            Finding(
                rule_id="ceres.rag.encoded_payload",
                severity=Severity.LOW,
                layer=Layer.RAG,
                file=rel,
                line=lineno,
                message="Large base64-looking blob inside RAG document.",
                recommendation="Verify the blob isn't a smuggled instruction or binary payload.",
                evidence=Evidence(matched_text_preview=m.group(0)[:60] + "..."),
                frameworks=FrameworkMap(owasp_llm=("LLM01",)),
            )
        )
        break  # one per doc is enough signal

    if _INVISIBLE_CHAR_RE.search(text):
        out.append(
            Finding(
                rule_id="ceres.rag.invisible_control_chars",
                severity=Severity.MEDIUM,
                layer=Layer.RAG,
                file=rel,
                message="Document contains zero-width / bidi-control characters.",
                recommendation="Normalize/strip invisible Unicode before indexing.",
                frameworks=FrameworkMap(owasp_llm=("LLM01",)),
            )
        )

    return out


def _line(text: str, lineno: int) -> str:
    lines = text.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""


def _finding_from_pattern(pat: Pattern, rel: str, lineno: int, snippet: str) -> Finding:
    sev = Severity(pat.severity)
    return Finding(
        rule_id=pat.rule_id,
        severity=sev,
        layer=Layer.RAG,
        file=rel,
        line=lineno,
        message=pat.description,
        recommendation="Review the document source, remove instruction-like content, or mark the document as untrusted for retrieval.",
        evidence=Evidence(matched_text_preview=snippet),
        frameworks=FrameworkMap(owasp_llm=("LLM01", "LLM04")),
    )


def _front_matter(text: str) -> dict[str, Any]:
    if not text.startswith("---\n"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        data = yaml.safe_load(parts[1])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _document_urls(text: str, metadata: dict[str, Any]) -> list[str]:
    urls = list(_LINK_RE.findall(text))
    source = metadata.get("source")
    if isinstance(source, str) and source.startswith(("http://", "https://")):
        urls.append(source)
    return urls


def _domain_allowed(host: str, allowed: list[str]) -> bool:
    normalized = host.lower().rstrip(".")
    return any(normalized == d.lower() or normalized.endswith("." + d.lower()) for d in allowed)
