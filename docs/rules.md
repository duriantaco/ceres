# Rule Catalog

This catalog documents implemented Ceres rules. Rule IDs are Ceres-owned and do
not copy upstream scanner IDs. Severity is the default emitted by the current
implementation; policy gates decide whether a severity fails CI.

Run the registry locally:

```bash
ceres list-rules
```

## Code, Prompt, And Agent Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.model.loader.remote_code_enabled` | Remote model code enabled | Critical | `from_pretrained(...)` or pipeline-style loader uses `trust_remote_code=True` while policy disallows it. |
| `ceres.model.loader.revision_unpinned` | Unpinned model loader revision | High | Hugging Face `from_pretrained(...)` call has no `revision`, `commit_hash`, or `git_revision` argument. |
| `ceres.model.loader.torch_unsafe_load` | Unsafe torch load | High | `torch.load(...)` is called without `weights_only=True`. |
| `ceres.model.loader.pickle_deserialize` | Pickle deserialization in code | High | Python code calls `pickle.load`, `pickle.loads`, or `pickle.Unpickler`. |
| `ceres.model.loader.joblib_deserialize` | Joblib deserialization in code | High | Python code calls `joblib.load(...)`, which is pickle-backed. |
| `ceres.ai_code.dynamic_execution` | Dynamic code execution | High | Python code calls `eval(...)` or `exec(...)`. |
| `ceres.agent.tool.shell_without_allowlist` | Shell tool without allowlist | Critical | Agent config or Python tool definition exposes shell/bash/command execution without explicit allowed commands. |
| `ceres.agent.tool.risky_tool_without_approval` | Risky tool without approval | Critical or High | `allowed_tools` includes shell, email, browser, network, or file-write tools without a human approval gate. |
| `ceres.agent.tool.description_prompt_injection` | Tool description prompt injection | High | Tool/MCP/OpenAPI metadata or Python tool docstrings contain instruction-like content that can steer an agent. |
| `ceres.agent.tool.sensitive_context_request` | Sensitive context request in tool metadata | Critical | Tool descriptions ask the agent to read, send, or exfiltrate secrets, credentials, local config, private keys, or environment data. |
| `ceres.agent.tool.cross_tool_instruction` | Cross-tool instruction | High | One tool description appears to define behavior for another tool or server. |
| `ceres.agent.tool.hidden_instruction_markup` | Hidden instruction markup in tool metadata | High | Tool descriptions contain hidden HTML/comments or invisible Unicode that can carry covert instructions. |
| `ceres.agent.tool.description_drift` | Tool description drift | High | Tool metadata description hash differs from the baseline, which can indicate an MCP tool-poisoning update. |
| `ceres.agent.tool.added` | Tool metadata added | High | Tool metadata exists in the current scan but not in the baseline. |
| `ceres.agent.tool.removed` | Tool metadata removed | Medium | Tool metadata existed in the baseline but is missing from the current scan. |
| `ceres.prompt.system_context_user_slot` | User slot in system prompt | Medium | Prompt template interpolates `{user_input}`, `{user}`, `{message}`, `{query}`, or `{question}` directly into system context. |
| `ceres.prompt.secret_literal` | Inline credential in AI prompt/config | Critical or High | Optional rule. When `code_policy.scan_inline_secrets=true`, flags obvious API keys or high-entropy secret-like values in prompts/configs/code. Generic secret scanning should remain in Skylos. |

## Model Artifact Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.model.artifact.format_not_allowed` | Disallowed model format | High | Model artifact format is outside `model_policy.allowed_formats`, excluding pickle formats handled by the pickle rule. |
| `ceres.model.artifact.hash_drift` | Model artifact hash drift | High | Model artifact SHA-256 differs from `.ceres/baseline.json`. |
| `ceres.model.artifact.pickle_format` | Pickle model artifact | Critical | Pickle-backed model artifact such as `.pkl`, `.pickle`, or `.joblib` is present and blocked by policy. |
| `ceres.model.artifact.pickle_opcode_risk` | Suspicious pickle opcode risk | Critical | Static pickle scan finds suspicious imports/opcodes, reducers, or parse errors that make deserialization unsafe. |
| `ceres.model.artifact.prefer_safetensors` | Prefer safetensors | Medium | PyTorch checkpoint-like file (`.pt`, `.pth`, `.bin`, `.ckpt`) is present; safetensors is preferred where possible. |
| `ceres.model.artifact.source_missing_or_unapproved` | Missing or unapproved model source | High | Model artifact lacks adjacent provenance metadata, or model source/config source is outside `approved_model_sources`. |
| `ceres.model.config.revision_unpinned` | Unpinned configured model reference | High | YAML/JSON config references a Hugging Face-style model without a pinned revision. |

## Safetensors And Tensor Rules

See [Model Security](model-security.md) for baseline format, policy knobs, and
limitations.

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.model.safetensors.header_invalid` | Invalid safetensors header | High | Safetensors file is truncated, non-JSON, malformed, has invalid metadata, invalid dtype/shape/offsets, or tensor byte lengths do not match metadata. |
| `ceres.model.safetensors.header_oversized` | Oversized safetensors header | High | Safetensors header length exceeds `model_policy.max_safetensors_header_bytes`. |
| `ceres.model.tensor.added` | Tensor added | Medium | Tensor/layer exists in the current safetensors file but not in baseline. |
| `ceres.model.tensor.removed` | Tensor removed | High | Tensor/layer existed in baseline but is missing from the current safetensors file. |
| `ceres.model.tensor.shape_changed` | Tensor shape changed | High | Tensor shape differs from baseline. |
| `ceres.model.tensor.dtype_changed` | Tensor dtype changed | Medium | Tensor dtype differs from baseline. |
| `ceres.model.tensor.hash_drift` | Tensor hash drift | Medium | Tensor byte hash differs from baseline. |
| `ceres.model.tensor.nan_or_inf` | Tensor NaN or infinity | High | Numeric tensor stats contain NaN or +/-Inf values. |
| `ceres.model.tensor.norm_drift` | Tensor norm drift | Medium | Tensor L2 norm differs from baseline beyond `tensor_norm_drift_ratio`. |
| `ceres.model.tensor.sparsity_drift` | Tensor sparsity drift | Medium | Tensor zero ratio differs from baseline beyond `tensor_sparsity_drift_ratio`. |
| `ceres.model.tensor.range_anomaly` | Tensor range anomaly | Medium | Tensor min/max absolute value exceeds `max_tensor_abs_value`. |
| `ceres.model.tensor.suspicious_name` | Suspicious tensor name | Low | Tensor/layer name contains configured marker text such as `backdoor`, `trigger`, `override`, `jailbreak`, `malicious`, or `admin`. |

## Tokenizer, Chat Template, And Adapter Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.model.tokenizer.special_token_drift` | Special token drift | High | `special_tokens_map.json` or `added_tokens.json` contains new special tokens compared with baseline. |
| `ceres.model.chat_template.drift` | Chat template drift | High | `tokenizer_config.json` chat template changed compared with baseline. |
| `ceres.model.lora.base_model_drift` | LoRA base model drift | High | `adapter_config.json` `base_model_name_or_path` changed compared with baseline. |

## Dataset Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.dataset.manifest_missing` | Dataset manifest missing | High | Dataset file is present but not covered by a `dataset.yaml` manifest entry. |
| `ceres.dataset.manifest_incomplete` | Dataset manifest incomplete | Medium | `dataset.yaml` is missing required dataset keys such as `name`, `version`, `owner`, or `files`. |
| `ceres.dataset.hash_missing` | Dataset hash missing | Medium | Manifest entry exists but has no `sha256`. |
| `ceres.dataset.hash_drift` | Dataset hash drift | High | Dataset file SHA-256 differs from the manifest declaration. |
| `ceres.dataset.manifest_stale_hash` | Dataset manifest stale hash | High | Dataset changed from baseline but manifest still points at the old hash. |
| `ceres.dataset.source_unapproved` | Dataset source unapproved | High | Dataset manifest source does not match `data_policy.allowed_sources` or entry allowlist. |
| `ceres.dataset.duplicate_flood` | Dataset duplicate flood | Medium | Duplicate row rate exceeds `data_policy.max_duplicate_rate`. |
| `ceres.dataset.label_distribution_drift` | Label distribution drift | Medium | Label distribution Jensen-Shannon divergence exceeds `data_policy.max_label_jsd` compared with baseline. |
| `ceres.dataset.rare_phrase_repetition` | Rare phrase repetition | Medium | Multiple new high-frequency trigrams appear compared with baseline, suggesting repeated trigger phrases or injected text. |

## Eval And Safety Config Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.eval.safety_eval_disabled` | Safety eval disabled | High | Safety eval or safety gate config is disabled, skipped, bypassed, or allowed to fail. |
| `ceres.eval.regression_gate_disabled` | Regression eval disabled | High | Regression eval or eval gate config is disabled, skipped, bypassed, or allowed to fail. |
| `ceres.eval.safety_filter_disabled` | Safety filter disabled | High | Content filters, safety filters, guardrails, or output redaction are disabled. |
| `ceres.eval.safety_threshold_low` | Safety threshold too low | High | Safety score threshold is below `eval_policy.min_safety_score`. |
| `ceres.eval.generation_temperature_high` | Generation temperature high | Medium | Generation temperature exceeds `eval_policy.max_generation_temperature`. |

## RAG Corpus Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.rag.index.user_docs_without_sanitizer` | User docs indexed without sanitizer | High | Python code adds user/upload/request documents to a vector index without an obvious sanitizer, scanner, or quarantine step. |
| `ceres.rag.retrieval.filter_missing` | RAG retrieval filter missing | High | Python retrieval call lacks tenant, metadata, namespace, or permission filter arguments. |
| `ceres.rag.retrieval.permission_after_retrieval` | Permission check after retrieval | High | A permission/tenant/access check appears after retrieval in the same function. |
| `ceres.rag.citations_disabled` | RAG citations disabled | Medium | RAG response citation requirements are disabled in configuration. |
| `ceres.rag.instruction.ignore_context` | Ignore-context instruction | High | RAG document tells the model to ignore or disregard previous/prior instructions. |
| `ceres.rag.instruction.system_override` | System override instruction | High or Medium | RAG document attempts to override the system prompt/developer message or declares a new model role. |
| `ceres.rag.instruction.secret_request` | Secret request instruction | High | RAG document tells the model to reveal secrets or send/leak an API key. |
| `ceres.rag.instruction.tool_request` | Tool invocation instruction | High | RAG document tells the model to call a tool, run a shell command, or execute code. |
| `ceres.rag.instruction.exfiltration` | Exfiltration instruction | High | RAG document mentions exfiltration of data. |
| `ceres.rag.hidden_instruction_markup` | Hidden instruction markup | High or Medium | RAG document contains hidden HTML elements or HTML comments with instruction-like text. |
| `ceres.rag.encoded_payload` | Encoded payload in RAG doc | Low | RAG document contains a large base64-looking blob. |
| `ceres.rag.invisible_control_chars` | Invisible control characters | Medium | RAG document contains zero-width or bidi-control Unicode characters. |
| `ceres.rag.source_metadata_missing` | RAG source metadata missing | Medium | `rag_policy.require_source_metadata=true` and document front matter lacks `source`. |
| `ceres.rag.owner_missing` | RAG owner metadata missing | Medium | `rag_policy.require_doc_owner=true` and document front matter lacks `owner`. |
| `ceres.rag.domain_unapproved` | RAG domain unapproved | High | RAG document links to a domain outside `rag_policy.allowed_domains`. |

## Supply Chain Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.supplychain.dependency_unpinned` | Dependency unpinned | Low | Optional rule. When `dependency_policy.scan_unpinned_dependencies=true`, requirements, `pyproject.toml`, or Poetry dependencies are checked for exact pins. |
| `ceres.supplychain.git_dependency_unpinned` | Git dependency unpinned | High | Git dependency is not pinned to a full 40-character commit SHA. |
| `ceres.supplychain.lockfile_missing` | Lockfile missing | Medium | Dependency manifest exists and `dependency_policy.require_lockfile=true`, but no recognized lockfile is present. |
| `ceres.supplychain.remote_script_pipe` | Remote script piped to interpreter | High | CI or Docker config pipes `curl`/`wget` output directly into `sh`, `bash`, `python`, or `python3`. |
| `ceres.supplychain.docker_image_unpinned` | Docker image unpinned | Medium | Dockerfile `FROM` image is not pinned by `@sha256:<digest>`. |
| `ceres.supplychain.vulnerable_dependency` | Vulnerable dependency | Critical, High, Medium, or Low | Optional `pip-audit` adapter reports a known dependency vulnerability. Severity follows the advisory when available. |
| `ceres.supplychain.scanner_unavailable` | External scanner unavailable | Low | Policy enables `pip-audit`, `osv-scanner`, or `gitleaks`, but the executable is not on `PATH`. |
| `ceres.supplychain.secret_scanner_hit.*` | External secret scanner hit | Critical | Optional `gitleaks` adapter reports a redacted secret hit. Generic secret scanning is off by default and should usually live in Skylos. |

## AI-BOM, Policy, And Engine Rules

| Rule ID | Name | Severity | What it catches |
|---|---|---:|---|
| `ceres.aibom.coverage_missing` | AI-BOM coverage missing | Low | Models/datasets exist without `ai-bom.json`, `ai-bom.json` is unreadable, or AI-BOM is missing model/dataset components. |
| `ceres.policy.waiver_expired` | Waiver expired | Medium | A configured waiver has expired and no longer suppresses matching findings. |
| `ceres.engine.analyzer_failed` | Analyzer failed | High | A Ceres analyzer raised an exception; the scan is incomplete and should not be treated as clean. |

## Optional Rules Off By Default

These rules exist for integration or AI-context edge cases but are not the Ceres
product wedge:

| Rule ID | Why optional |
|---|---|
| `ceres.prompt.secret_literal` | Inline secret checks are off by default. Use Skylos for generic leak detection. |
| `ceres.supplychain.secret_scanner_hit.*` | Requires `dependency_policy.run_gitleaks=true` and `gitleaks` on `PATH`; generic leak scanning should normally run outside Ceres. |
