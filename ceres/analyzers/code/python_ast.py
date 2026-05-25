from __future__ import annotations

import ast
import re
from pathlib import Path

from ceres.analyzers.base import AnalyzerContext
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity

_HF_LOADER_NAMES = {"from_pretrained"}
_PIPELINE_NAMES = {"pipeline"}
_PICKLE_LOAD_NAMES = {"load", "loads", "Unpickler"}
_AGENT_TOOL_NAMES = {"Tool", "StructuredTool", "ShellTool", "ToolNode"}

_REVISION_KWARGS = {"revision", "commit_hash", "git_revision"}
_RAG_RETRIEVAL_NAMES = {
    "similarity_search",
    "asimilarity_search",
    "max_marginal_relevance_search",
    "amax_marginal_relevance_search",
    "get_relevant_documents",
    "aget_relevant_documents",
    "retrieve",
    "aretrieve",
}
_RAG_RETRIEVER_TARGETS = {
    "retriever",
    "vector",
    "vectorstore",
    "vector_store",
    "chroma",
    "pinecone",
    "weaviate",
    "qdrant",
    "milvus",
    "faiss",
    "index",
}
_RAG_FILTER_KWARGS = {
    "filter",
    "filters",
    "where",
    "namespace",
    "tenant",
    "tenant_id",
    "user_id",
    "metadata_filter",
    "pre_filter",
    "expr",
}
_RAG_INGEST_NAMES = {
    "add_documents",
    "aadd_documents",
    "add_texts",
    "aadd_texts",
    "from_documents",
    "index_documents",
    "upsert",
}
_RAG_SOURCE_RE = re.compile(r"(user|upload|uploaded|request|file|files|raw|untrusted|customer|tenant)", re.IGNORECASE)
_RAG_SANITIZER_RE = re.compile(r"(sanitize|scrub|filter|moderate|scan|validate|quarantine|redact|pii|allowlist)", re.IGNORECASE)
_RAG_PERMISSION_RE = re.compile(r"(permission|authorize|authorise|auth|tenant|acl|access|policy|can_access|allowed)", re.IGNORECASE)

_SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|secret|password|token|access[_-]?key|private[_-]?key|bearer)",
    re.IGNORECASE,
)
_OBVIOUS_PLACEHOLDER_RE = re.compile(
    r"^(?:|<.+>|\{\{.+\}\}|\${.+}|\$\(.+\)|x{3,}|\.{3,}|todo|tbd|changeme|your[_-]?\w*)$",
    re.IGNORECASE,
)


def run(ctx: AnalyzerContext) -> list[Finding]:
    findings: list[Finding] = []
    pol = ctx.policy.code_policy
    mpol = ctx.policy.model_policy
    for path in ctx.inventory.code:
        if path.suffix.lower() != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text, filename=str(path))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        findings.extend(_scan_module(tree, text, path, ctx, pol, mpol))
    return findings


def _scan_module(
    tree: ast.AST, text: str, path: Path, ctx: AnalyzerContext, pol, mpol
) -> list[Finding]:
    rel = ctx.rel(path)
    src_lines = text.splitlines()
    findings: list[Finding] = []

    aliases: dict[str, str] = {}

    class Visitor(ast.NodeVisitor):
        def generic_visit(self, node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                self.visit(child)

        def visit_Import(self, node: ast.Import) -> None:
            for n in node.names:
                aliases[n.asname or n.name] = n.name
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if node.module is None:
                return self.generic_visit(node)
            for n in node.names:
                aliases[n.asname or n.name] = f"{node.module}.{n.name}"
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            _check_call(node)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            if pol.scan_inline_secrets:
                _check_secret_assign(node)
            self.generic_visit(node)

    def _qualified(func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return aliases.get(func.id, func.id)
        if isinstance(func, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                base = aliases.get(cur.id, cur.id)
                parts.append(base)
            return ".".join(reversed(parts))
        return ""

    def _kw(node: ast.Call, name: str) -> ast.AST | None:
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _line_snippet(line: int) -> str:
        if 1 <= line <= len(src_lines):
            return src_lines[line - 1].strip()[:160]
        return ""

    def _add(
        rule_id: str,
        severity: Severity,
        layer: Layer,
        node: ast.AST,
        message: str,
        recommendation: str,
        owasp_llm: tuple[str, ...] = (),
        owasp_ml: tuple[str, ...] = (),
    ) -> None:
        line = getattr(node, "lineno", None)
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                layer=layer,
                file=rel,
                line=line,
                column=getattr(node, "col_offset", None),
                message=message,
                recommendation=recommendation,
                evidence=Evidence(matched_text_preview=_line_snippet(line) if line else None),
                frameworks=FrameworkMap(owasp_llm=owasp_llm, owasp_ml=owasp_ml),
            )
        )

    def _check_call(node: ast.Call) -> None:
        qual = _qualified(node.func)
        tail = qual.rsplit(".", 1)[-1]

        if pol.block_eval_exec and qual in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            _add(
                "ceres.ai_code.dynamic_execution",
                Severity.HIGH,
                Layer.CODE,
                node,
                f"Use of {tail}() can execute arbitrary code.",
                "Replace dynamic execution with explicit dispatch or a sandboxed evaluator.",
                owasp_llm=("LLM02",),
                owasp_ml=("ML06",),
            )

        if (
            pol.block_pickle_load
            and (qual.startswith("pickle.") or qual.startswith("cPickle."))
            and tail in _PICKLE_LOAD_NAMES
        ):
            _add(
                "ceres.model.loader.pickle_deserialize",
                Severity.HIGH,
                Layer.CODE,
                node,
                f"pickle.{tail}() can execute arbitrary code during deserialization.",
                "Use safetensors / ONNX, or constrain pickle with fickling/picklescan + an allowlist.",
                owasp_llm=("LLM03", "LLM05"),
                owasp_ml=("ML06",),
            )

        if pol.block_pickle_load and qual.endswith("joblib.load"):
            _add(
                "ceres.model.loader.joblib_deserialize",
                Severity.HIGH,
                Layer.CODE,
                node,
                "joblib.load() is pickle-based and can execute arbitrary code.",
                "Prefer safetensors/ONNX, or scan artifacts with picklescan/fickling before load.",
                owasp_ml=("ML06",),
            )

        if pol.block_unsafe_torch_load and qual.endswith("torch.load"):
            weights_only = _kw(node, "weights_only")
            safe = isinstance(weights_only, ast.Constant) and weights_only.value is True
            if not safe:
                _add(
                    "ceres.model.loader.torch_unsafe_load",
                    Severity.HIGH,
                    Layer.CODE,
                    node,
                    "torch.load() called without weights_only=True; can execute pickled code.",
                    "Pass weights_only=True or migrate the artifact to safetensors.",
                    owasp_llm=("LLM03",),
                    owasp_ml=("ML06",),
                )

        if tail in _HF_LOADER_NAMES or tail in _PIPELINE_NAMES:
            trc = _kw(node, "trust_remote_code")
            if (
                pol.block_trust_remote_code
                and not mpol.allow_trust_remote_code
                and isinstance(trc, ast.Constant)
                and trc.value is True
            ):
                _add(
                    "ceres.model.loader.remote_code_enabled",
                    Severity.CRITICAL,
                    Layer.CODE,
                    node,
                    "Model loader uses trust_remote_code=True; remote model code will execute on load.",
                    "Set trust_remote_code=False, pin a vetted revision, or add an explicit waiver.",
                    owasp_llm=("LLM03", "LLM05"),
                    owasp_ml=("ML06",),
                )
            if mpol.require_revision_pin and tail in _HF_LOADER_NAMES:
                rev = None
                for k in _REVISION_KWARGS:
                    if _kw(node, k) is not None:
                        rev = k
                        break
                if rev is None:
                    _add(
                        "ceres.model.loader.revision_unpinned",
                        Severity.HIGH,
                        Layer.MODEL,
                        node,
                        "Model loader does not pin a revision; the remote model can change without notice.",
                        "Pass revision='<commit-sha>' when calling from_pretrained().",
                        owasp_llm=("LLM03",),
                        owasp_ml=("ML06",),
                    )

        if pol.require_tool_allowlist and tail in _AGENT_TOOL_NAMES:
            name_arg = _kw(node, "name")
            if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                nm = name_arg.value.lower()
                if any(t in nm for t in ("shell", "bash", "exec", "command")):
                    if _kw(node, "allowlist") is None and _kw(node, "allowed_commands") is None:
                        _add(
                            "ceres.agent.tool.shell_without_allowlist",
                            Severity.CRITICAL,
                            Layer.AGENT,
                            node,
                            f"Agent tool '{name_arg.value}' looks shell-capable but has no allowlist.",
                            "Pass an explicit allowlist of safe commands, or remove shell access.",
                            owasp_llm=("LLM07", "LLM08"),
                        )

    def _scan_rag_flow(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        calls.sort(key=lambda n: getattr(n, "lineno", 0))

        permission_lines = [
            getattr(n, "lineno", 0)
            for n in calls
            if _RAG_PERMISSION_RE.search(_qualified(n.func))
        ]
        sanitizer_lines = [
            getattr(n, "lineno", 0)
            for n in calls
            if _RAG_SANITIZER_RE.search(_qualified(n.func))
        ]

        first_retrieval_without_prior_permission: ast.Call | None = None
        first_retrieval_without_filter: ast.Call | None = None
        first_user_ingest_without_sanitizer: ast.Call | None = None

        for call in calls:
            line = getattr(call, "lineno", 0)
            qual = _qualified(call.func)
            if _is_rag_retrieval(qual):
                has_filter = any(kw.arg in _RAG_FILTER_KWARGS for kw in call.keywords if kw.arg)
                if ctx.policy.rag_policy.require_retrieval_filter and not has_filter and first_retrieval_without_filter is None:
                    first_retrieval_without_filter = call
                if (
                    any(p > line for p in permission_lines)
                    and not any(0 < p < line for p in permission_lines)
                    and first_retrieval_without_prior_permission is None
                ):
                    first_retrieval_without_prior_permission = call

            if (
                ctx.policy.rag_policy.require_ingest_sanitizer
                and _is_rag_ingest(qual)
                and _call_uses_user_docs(call)
                and not any(0 < s < line for s in sanitizer_lines)
                and first_user_ingest_without_sanitizer is None
            ):
                first_user_ingest_without_sanitizer = call

        if first_retrieval_without_filter is not None:
            _add(
                "ceres.rag.retrieval.filter_missing",
                Severity.HIGH,
                Layer.RAG,
                first_retrieval_without_filter,
                "RAG retrieval call has no tenant, metadata, namespace, or permission filter.",
                "Pass an explicit filter/namespace/tenant constraint before retrieving from shared or private corpora.",
                owasp_llm=("LLM02", "LLM05"),
            )

        if first_retrieval_without_prior_permission is not None:
            _add(
                "ceres.rag.retrieval.permission_after_retrieval",
                Severity.HIGH,
                Layer.RAG,
                first_retrieval_without_prior_permission,
                "Permission or tenant check appears after retrieval in the same function.",
                "Check user/tenant permissions before querying the vector index.",
                owasp_llm=("LLM02", "LLM05"),
            )

        if first_user_ingest_without_sanitizer is not None:
            _add(
                "ceres.rag.index.user_docs_without_sanitizer",
                Severity.HIGH,
                Layer.RAG,
                first_user_ingest_without_sanitizer,
                "User-controlled documents are indexed without an obvious sanitizer, scanner, or quarantine step.",
                "Scan, sanitize, and quarantine user-uploaded documents before adding them to a retrieval index.",
                owasp_llm=("LLM01", "LLM03", "LLM05"),
            )

    def _is_rag_retrieval(qual: str) -> bool:
        lower = qual.lower()
        tail = lower.rsplit(".", 1)[-1]
        if tail in _RAG_RETRIEVAL_NAMES:
            return True
        if tail in {"invoke", "query", "search"} and any(marker in lower for marker in _RAG_RETRIEVER_TARGETS):
            return True
        return False

    def _is_rag_ingest(qual: str) -> bool:
        lower = qual.lower()
        tail = lower.rsplit(".", 1)[-1]
        return tail in _RAG_INGEST_NAMES and any(marker in lower for marker in _RAG_RETRIEVER_TARGETS)

    def _call_uses_user_docs(call: ast.Call) -> bool:
        chunks: list[str] = []
        for arg in call.args:
            chunks.append(_unparse(arg))
        for kw in call.keywords:
            if kw.value is not None:
                chunks.append(_unparse(kw.value))
        return bool(_RAG_SOURCE_RE.search(" ".join(chunks)))

    def _unparse(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:  # pragma: no cover - ast.unparse is best-effort
            return ""

    def _check_secret_assign(node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return
        val = node.value.value
        if len(val) < 12 or _OBVIOUS_PLACEHOLDER_RE.match(val):
            return
        for target in node.targets:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if not name or not _SECRET_NAME_RE.search(name):
                continue
            if val.startswith(("$", "{{", "${")) or val.lower() in {"none", "null"}:
                continue
            _add(
                "ceres.prompt.secret_literal",
                Severity.HIGH,
                Layer.CODE,
                node,
                f"Likely hard-coded secret assigned to '{name}'.",
                "Move the value to an environment variable or a secrets manager.",
                owasp_llm=("LLM06",),
            )
            break

    Visitor().visit(tree)
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_rag_flow(fn)
    return findings
