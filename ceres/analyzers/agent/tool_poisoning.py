from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

from ceres.analyzers.base import AnalyzerContext
from ceres.analyzers.rag.injection_patterns import find_injections
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity


_DESCRIPTION_KEYS = {"description", "desc", "summary"}
_TOOL_CONTAINER_KEYS = {"tools", "functions"}
_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
_PY_TOOL_DECORATORS = {"tool", "mcp.tool", "server.tool"}
_PY_TOOL_CALLS = {"Tool", "StructuredTool", "ShellTool", "FunctionTool", "tool"}

_CONCEALMENT_RE = re.compile(
    r"\b("
    r"do\s+not\s+(?:mention|tell|show|reveal|disclose)|"
    r"don't\s+(?:mention|tell|show|reveal|disclose)|"
    r"without\s+(?:telling|notifying|informing)|"
    r"secretly|silently|conceal|hide\s+(?:this|the|your)"
    r")\b",
    re.IGNORECASE,
)
_SENSITIVE_RE = re.compile(
    r"(?:"
    r"(?:read|open|access|load|send|pass|include|transmit|upload|post)\b.{0,80}"
    r"(?:~/?\.ssh|id_rsa|mcp\.json|\.env|/etc/passwd|api[_\s-]?key|secret|token|credential|password|private[_\s-]?key|env(?:ironment)?\s+variable)"
    r"|exfiltrat"
    r")",
    re.IGNORECASE | re.DOTALL,
)
_SYSTEM_STYLE_RE = re.compile(
    r"<\s*/?\s*(?:important|system|developer|hidden|instruction|secret)\s*>|\b(?:system|developer)\s+message\b",
    re.IGNORECASE,
)
_HIDDEN_HTML_RE = re.compile(
    r"<[^>]+style=[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^\"']*[\"'][^>]*>",
    re.IGNORECASE,
)
_HTML_COMMENT_RE = re.compile(r"<!--(.+?)-->", re.DOTALL)
_INVISIBLE_CHAR_RE = re.compile(
    "["
    + "".join(
        f"{chr(lo)}-{chr(hi)}"
        for lo, hi in (
            (0x200B, 0x200F),
            (0x202A, 0x202E),
            (0x2060, 0x2064),
            (0xFEFF, 0xFEFF),
        )
    )
    + "]"
)


@dataclass(frozen=True)
class ToolDescriptor:
    file: Path
    rel: str
    name: str
    description: str
    source: str
    field: str
    line: int | None = None

    @property
    def identity(self) -> str:
        if self.name:
            return f"{self.rel}#tool:{_stable_id_part(self.name)}:{_stable_id_part(self.field)}"
        return f"{self.rel}#{self.source}"


def run(ctx: AnalyzerContext) -> list[Finding]:
    if not ctx.policy.code_policy.scan_tool_descriptions:
        return []

    descriptors = extract_tool_descriptors(ctx.inventory.configs, ctx.inventory.code, ctx.root)
    findings: list[Finding] = []
    tool_names = {d.name for d in descriptors if d.name}
    current_by_id = {d.identity: d for d in descriptors}
    baseline_tools = (ctx.baseline or {}).get("tools")

    for descriptor in descriptors:
        findings.extend(_scan_descriptor(descriptor, tool_names))
        baseline = baseline_tools.get(descriptor.identity) if isinstance(baseline_tools, dict) else None
        if isinstance(baseline, dict):
            baseline_hash = baseline.get("description_sha256")
            current_hash = _sha256_text(descriptor.description)
            if baseline_hash and baseline_hash != current_hash:
                findings.append(
                    Finding(
                        rule_id="ceres.agent.tool.description_drift",
                        severity=Severity.HIGH,
                        layer=Layer.AGENT,
                        file=descriptor.rel,
                        line=descriptor.line,
                        message=f"Tool metadata for '{descriptor.name}' changed compared with baseline.",
                        recommendation=(
                            "Review the full tool description before allowing this tool in agent context; "
                            "description drift can indicate MCP tool poisoning or a malicious update."
                        ),
                        evidence=Evidence(
                            matched_text_preview=_preview(descriptor.description),
                            source=descriptor.source,
                            extra={"baseline_sha256": baseline_hash, "current_sha256": current_hash},
                        ),
                        frameworks=FrameworkMap(owasp_llm=("LLM01", "LLM05", "LLM08")),
                    )
                )

    if isinstance(baseline_tools, dict):
        for identity, descriptor in current_by_id.items():
            if identity not in baseline_tools:
                findings.append(
                    Finding(
                        rule_id="ceres.agent.tool.added",
                        severity=Severity.HIGH,
                        layer=Layer.AGENT,
                        file=descriptor.rel,
                        line=descriptor.line,
                        message=f"Tool metadata for '{descriptor.name}' was added after the baseline.",
                        recommendation=(
                            "Review newly introduced tool metadata before exposing it to an agent; "
                            "new MCP tools can introduce poisoned descriptions or expanded capability."
                        ),
                        evidence=Evidence(matched_text_preview=_preview(descriptor.description), source=descriptor.source),
                        frameworks=FrameworkMap(owasp_llm=("LLM01", "LLM05", "LLM08")),
                    )
                )
        for identity, baseline in baseline_tools.items():
            if identity in current_by_id or not isinstance(baseline, dict):
                continue
            findings.append(
                Finding(
                    rule_id="ceres.agent.tool.removed",
                    severity=Severity.MEDIUM,
                    layer=Layer.AGENT,
                    file=_baseline_file(identity),
                    message=f"Tool metadata for '{baseline.get('name', '<unknown>')}' was removed after the baseline.",
                    recommendation=(
                        "Review removed tool metadata; removal or replacement can indicate unexpected agent capability drift."
                    ),
                    evidence=Evidence(
                        matched_text_preview=str(baseline.get("description_preview", ""))[:160],
                        source=identity,
                    ),
                    frameworks=FrameworkMap(owasp_llm=("LLM05", "LLM08")),
                )
            )

    return findings


def extract_tool_descriptors(
    config_paths: list[Path],
    code_paths: list[Path],
    root: Path,
) -> list[ToolDescriptor]:
    descriptors: list[ToolDescriptor] = []
    for path in config_paths:
        descriptors.extend(_extract_from_config(path, root))
    for path in code_paths:
        descriptors.extend(_extract_from_python(path, root))
    return descriptors


def descriptor_baseline(descriptors: list[ToolDescriptor]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for descriptor in descriptors:
        out[descriptor.identity] = {
            "name": descriptor.name,
            "description_sha256": _sha256_text(descriptor.description),
            "description_preview": _preview(descriptor.description),
        }
    return out


def _extract_from_config(path: Path, root: Path) -> list[ToolDescriptor]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    data: Any
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return []
    elif suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
    elif suffix == ".toml":
        try:
            data = tomllib.loads(raw)
        except tomllib.TOMLDecodeError:
            return []
    else:
        return []

    if data is None:
        return []

    rel = _rel(path, root)
    out: list[ToolDescriptor] = []
    _walk_structured(data, path, rel, [], raw, out)
    return out


def _walk_structured(
    node: Any,
    file: Path,
    rel: str,
    path: list[str],
    raw: str,
    out: list[ToolDescriptor],
) -> None:
    if isinstance(node, dict):
        if "paths" in node and isinstance(node["paths"], dict):
            _extract_openapi_operations(node["paths"], file, rel, [*path, "paths"], raw, out)

        for key in _TOOL_CONTAINER_KEYS:
            value = node.get(key)
            if value is not None:
                _extract_tool_container(value, file, rel, [*path, key], raw, out)

        if _looks_like_tool_object(node, path):
            _add_descriptions_from_tool_object(node, file, rel, path, raw, out)

        for key, value in node.items():
            if key in _TOOL_CONTAINER_KEYS or key == "paths":
                continue
            _walk_structured(value, file, rel, [*path, str(key)], raw, out)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            if not path and isinstance(item, dict) and _looks_like_bare_tool_object(item):
                _add_descriptions_from_tool_object(item, file, rel, [f"[{i}]"], raw, out)
                continue
            _walk_structured(item, file, rel, [*path, f"[{i}]"], raw, out)


def _extract_tool_container(
    node: Any,
    file: Path,
    rel: str,
    path: list[str],
    raw: str,
    out: list[ToolDescriptor],
) -> None:
    if isinstance(node, dict):
        for name, body in node.items():
            if isinstance(body, dict):
                _add_descriptions_from_tool_object(body, file, rel, [*path, str(name)], raw, out, str(name))
    elif isinstance(node, list):
        for i, body in enumerate(node):
            if isinstance(body, dict):
                _add_descriptions_from_tool_object(body, file, rel, [*path, f"[{i}]"], raw, out)


def _extract_openapi_operations(
    paths: dict[str, Any],
    file: Path,
    rel: str,
    path: list[str],
    raw: str,
    out: list[ToolDescriptor],
) -> None:
    for route, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_path = [*path, str(route), method]
            name = _string_field(operation, ("operationId", "name")) or f"{method.upper()} {route}"
            _add_descriptions_from_tool_object(operation, file, rel, op_path, raw, out, name)


def _looks_like_tool_object(node: dict[str, Any], path: list[str]) -> bool:
    if not any(k in node for k in _DESCRIPTION_KEYS):
        return False
    path_tokens = {p.strip("[]").lower() for p in path}
    if path_tokens & _TOOL_CONTAINER_KEYS:
        return True
    if node.get("type") == "function" or isinstance(node.get("function"), dict):
        return True
    return any(k in node for k in ("input_schema", "inputSchema", "parameters", "schema"))


def _looks_like_bare_tool_object(node: dict[str, Any]) -> bool:
    return any(k in node for k in _DESCRIPTION_KEYS) and any(k in node for k in ("name", "id", "operationId"))


def _add_descriptions_from_tool_object(
    node: dict[str, Any],
    file: Path,
    rel: str,
    path: list[str],
    raw: str,
    out: list[ToolDescriptor],
    fallback_name: str | None = None,
) -> None:
    target = node.get("function") if isinstance(node.get("function"), dict) else node
    name = _string_field(target, ("name", "operationId", "id")) or fallback_name or ".".join(path[-2:])
    for desc_path, desc in _iter_description_fields(target, path):
        out.append(
            ToolDescriptor(
                file=file,
                rel=rel,
                name=name,
                description=desc,
                source=".".join(desc_path),
                field=".".join(desc_path[len(path) :]) or desc_path[-1],
                line=_line_for_description(raw, desc),
            )
        )


def _iter_description_fields(node: Any, path: list[str]) -> list[tuple[list[str], str]]:
    out: list[tuple[list[str], str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = [*path, str(key)]
            if key in _DESCRIPTION_KEYS and isinstance(value, str) and value.strip():
                out.append((child_path, value))
            elif isinstance(value, (dict, list)):
                out.extend(_iter_description_fields(value, child_path))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            out.extend(_iter_description_fields(item, [*path, f"[{i}]"]))
    return out


def _extract_from_python(path: Path, root: Path) -> list[ToolDescriptor]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        tree = ast.parse(raw)
    except SyntaxError:
        return []

    rel = _rel(path, root)
    out: list[ToolDescriptor] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _has_tool_decorator(node):
            decorator_description = _decorated_tool_description(node)
            if decorator_description:
                name = _decorated_tool_name(node) or node.name
                out.append(
                    ToolDescriptor(
                        file=path,
                        rel=rel,
                        name=name,
                        description=decorator_description,
                        source=f"{node.name}.decorator.description",
                        field="decorator.description",
                        line=node.lineno,
                    )
                )
            doc = ast.get_docstring(node)
            if doc:
                out.append(
                    ToolDescriptor(
                        file=path,
                        rel=rel,
                        name=_decorated_tool_name(node) or node.name,
                        description=doc,
                        source=f"{node.name}.__doc__",
                        field="docstring",
                        line=node.lineno,
                    )
                )
        elif isinstance(node, ast.Call) and _is_tool_constructor(node.func):
            desc = _string_kw(node, "description")
            if desc:
                name = _string_kw(node, "name") or _first_string_arg(node) or _tail_name(node.func) or "tool"
                out.append(
                    ToolDescriptor(
                        file=path,
                        rel=rel,
                        name=name,
                        description=desc,
                        source=f"{name}.description",
                        field="description",
                        line=getattr(node, "lineno", None),
                    )
                )
    return out


def _has_tool_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(_is_tool_decorator(d) for d in node.decorator_list)


def _decorated_tool_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and _is_tool_decorator(decorator):
            name = _string_kw(decorator, "name") or _first_string_arg(decorator)
            if name:
                return name
    return None


def _decorated_tool_description(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and _is_tool_decorator(decorator):
            desc = _string_kw(decorator, "description")
            if desc:
                return desc
    return None


def _is_tool_decorator(node: ast.AST) -> bool:
    tail = _tail_name(node) or ""
    return tail in _PY_TOOL_DECORATORS or tail.split(".")[-1] == "tool"


def _is_tool_constructor(node: ast.AST) -> bool:
    tail = _tail_name(node) or ""
    parts = tail.split(".")
    if parts[-1] in _PY_TOOL_CALLS:
        return True
    return len(parts) >= 2 and parts[-2] in _PY_TOOL_CALLS and parts[-1] in {"from_function", "from_defaults"}


def _tail_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return _tail_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _tail_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _string_kw(node: ast.Call, name: str) -> str | None:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _first_string_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _scan_descriptor(descriptor: ToolDescriptor, tool_names: set[str]) -> list[Finding]:
    text = descriptor.description
    out: list[Finding] = []

    injection_hits = find_injections(text)
    if injection_hits or _CONCEALMENT_RE.search(text) or _SYSTEM_STYLE_RE.search(text):
        out.append(
            Finding(
                rule_id="ceres.agent.tool.description_prompt_injection",
                severity=Severity.HIGH,
                layer=Layer.AGENT,
                file=descriptor.rel,
                line=descriptor.line,
                message=f"Tool description for '{descriptor.name}' contains instruction-like content.",
                recommendation=(
                    "Keep tool descriptions narrowly about tool behavior; remove instructions that tell the model "
                    "to ignore policy, hide actions, or alter its behavior."
                ),
                evidence=Evidence(matched_text_preview=_preview(text), source=descriptor.source),
                frameworks=FrameworkMap(owasp_llm=("LLM01", "LLM05", "LLM08")),
            )
        )

    if _SENSITIVE_RE.search(text):
        out.append(
            Finding(
                rule_id="ceres.agent.tool.sensitive_context_request",
                severity=Severity.CRITICAL,
                layer=Layer.AGENT,
                file=descriptor.rel,
                line=descriptor.line,
                message=f"Tool description for '{descriptor.name}' asks the agent to access sensitive context.",
                recommendation=(
                    "Remove requests for secrets, local credentials, private files, or environment data from tool metadata. "
                    "Tool descriptions should not request data exfiltration paths."
                ),
                evidence=Evidence(matched_text_preview=_preview(text), source=descriptor.source),
                frameworks=FrameworkMap(owasp_llm=("LLM01", "LLM02", "LLM05", "LLM08")),
            )
        )

    other_tool = _referenced_other_tool(text, descriptor.name, tool_names)
    if other_tool is not None:
        out.append(
            Finding(
                rule_id="ceres.agent.tool.cross_tool_instruction",
                severity=Severity.HIGH,
                layer=Layer.AGENT,
                file=descriptor.rel,
                line=descriptor.line,
                message=f"Tool description for '{descriptor.name}' appears to steer another tool ('{other_tool}').",
                recommendation=(
                    "Keep MCP/tool descriptions self-contained. Do not let one tool define behavior for other tools or servers."
                ),
                evidence=Evidence(matched_text_preview=_preview(text), source=descriptor.source),
                frameworks=FrameworkMap(owasp_llm=("LLM01", "LLM05", "LLM08")),
            )
        )

    if _HIDDEN_HTML_RE.search(text) or _INVISIBLE_CHAR_RE.search(text) or _instruction_like_html_comment(text):
        out.append(
            Finding(
                rule_id="ceres.agent.tool.hidden_instruction_markup",
                severity=Severity.HIGH,
                layer=Layer.AGENT,
                file=descriptor.rel,
                line=descriptor.line,
                message=f"Tool description for '{descriptor.name}' contains hidden or covert instruction markup.",
                recommendation="Strip hidden HTML/comments and invisible Unicode from tool metadata before exposing it to an agent.",
                evidence=Evidence(matched_text_preview=_preview(text), source=descriptor.source),
                frameworks=FrameworkMap(owasp_llm=("LLM01", "LLM05")),
            )
        )

    return out


def _referenced_other_tool(text: str, current_name: str, tool_names: set[str]) -> str | None:
    lower = text.lower()
    if "mcp_tool_" in lower:
        return "mcp_tool_*"
    if not re.search(r"\b(?:call|invoke|must|should|override|route|redirect|force|send|pass)\b", lower):
        return None
    current = current_name.lower()
    for name in sorted(tool_names):
        normalized = name.lower()
        if normalized and normalized != current and re.search(rf"\b{re.escape(normalized)}\b", lower):
            return name
    if re.search(r"\b(?:another|other|trusted)\s+(?:tool|server)\b", lower):
        return "another tool/server"
    return None


def _instruction_like_html_comment(text: str) -> bool:
    for match in _HTML_COMMENT_RE.finditer(text):
        inner = match.group(1).lower()
        if any(kw in inner for kw in ("ignore", "system prompt", "you are", "reveal", "tool", "exec", "secret")):
            return True
    return False


def _line_for_description(raw: str, description: str) -> int | None:
    first = next((line.strip() for line in description.splitlines() if line.strip()), "")
    if not first:
        return None
    needle = first[:80]
    for i, line in enumerate(raw.splitlines(), start=1):
        if needle in line:
            return i
    return None


def _string_field(node: dict[str, Any], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = node.get(name)
        if isinstance(value, str) and value:
            return value
    return None


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _stable_id_part(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "_", value.strip().lower()).strip("_") or "unknown"


def _baseline_file(identity: str) -> str:
    return identity.split("#", 1)[0] if "#" in identity else "<baseline>"


def _preview(text: str) -> str:
    return " ".join(text.strip().split())[:160]


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
