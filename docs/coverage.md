# What Ceres Catches

Ceres combines static repo analysis with baseline comparison. This gives it
coverage over AI-specific surfaces that generic SAST, SCA, and secret scanners
usually miss.

## Code And Agent Tools

- `trust_remote_code=True` in model loaders
- unpinned Hugging Face `from_pretrained(...)` revisions
- unsafe `torch.load(...)`
- `pickle.load`, `pickle.loads`, `pickle.Unpickler`, and `joblib.load`
- `eval(...)` and `exec(...)`
- shell-capable agent tools without allowlists
- high-impact tools in `allowed_tools` without human approval
- poisoned tool/MCP descriptions, including hidden instructions, sensitive
  context requests, cross-tool steering, and baseline added/removed/drift checks
- user input inserted directly into system prompt templates

## Model Artifacts

- pickle-backed model formats
- PyTorch checkpoint formats where safetensors is preferred
- model artifact formats outside policy
- missing or unapproved source/provenance metadata
- model hash drift against baseline
- suspicious pickle opcodes or parse failures
- invalid or oversized safetensors headers
- tensor added/removed/shape/dtype/hash drift
- tensor NaN/Inf/range/norm/sparsity anomalies
- GGUF header/metadata parsing and architecture/metadata/tensor-count drift
- ONNX protobuf metadata parsing and opset/operator/metadata drift
- tokenizer, chat-template, and LoRA base-model drift

## Datasets

- missing or incomplete dataset manifests
- missing, stale, or mismatched dataset hashes
- unapproved dataset sources
- duplicate-rate spikes
- label distribution drift against baseline
- repeated rare phrase changes that can indicate trigger injection

## Eval And Safety Config

- disabled or skipped safety eval gates
- disabled regression eval gates
- disabled content filters, guardrails, or output redaction
- safety score thresholds below policy
- generation temperatures above policy

## RAG Corpus

- user-uploaded documents indexed without sanitizer/scanner/quarantine calls
- retrieval calls missing tenant, metadata, namespace, or permission filters
- permission or tenant checks that happen after retrieval
- disabled RAG citation requirements
- instructions to ignore prior/system/developer messages
- instructions to reveal secrets, invoke tools, execute code, or exfiltrate data
- hidden HTML and instruction-like comments
- base64-looking payloads
- zero-width and bidi control characters
- missing document source/owner metadata when policy requires it
- links to unapproved domains

## Supply Chain, AI-BOM, And Engine

- unpinned dependencies and git dependencies
- missing lockfiles when required
- remote installer scripts piped directly into interpreters
- Docker images not pinned by digest
- optional `pip-audit` vulnerability findings
- optional `gitleaks` findings, off by default
- missing or stale `ai-bom.json` coverage
- expired waivers
- analyzer failures surfaced as incomplete scans
