<p align="center">
  <img src="assets/ceres-mark.svg" alt="Ceres logo" width="96" height="96">
</p>

# Ceres

**Developer-first AI security scanner.** Ceres is AI-SAST for repos: it inspects
your code, prompts, configs, model artifacts, datasets, RAG docs, and AI
supply chain for the security issues that traditional SAST/SCA tools miss. It
runs locally, in pre-commit, and in CI.

```text
ceres scan .
```

## What Ceres checks

| Layer       | Examples |
|-------------|----------|
| Code        | `trust_remote_code=True`, `pickle.load`, `torch.load` without `weights_only=True`, `eval`/`exec`, unrestricted agent tools, risky tools without approval, poisoned tool/MCP descriptions |
| Models      | `.pkl`/`.pickle` artifacts, unsafe formats, unknown source/provenance, suspicious pickle opcodes, missing/changed SHA-256, safetensors tensor/layer drift, NaN/Inf/range anomalies, tokenizer / chat-template / LoRA-base drift |
| Datasets    | missing manifest, missing/stale hash, source not in allowlist, duplicate-rate spikes, label distribution drift vs. baseline, sudden rare-trigger trigrams |
| Eval/safety | disabled safety or regression eval gates, lowered safety thresholds, disabled filters/guardrails, high generation temperature |
| RAG corpus  | prompt-injection phrases (`ignore previous instructions`, etc.), unsafe user-doc indexing, missing retrieval filters, permission checks after retrieval, hidden HTML / display:none, HTML comments with instructions, zero-width / bidi control chars, large base64 blobs |
| Prompts     | user input templated into system context; optional inline secret checks when explicitly enabled |
| Supply chain| unpinned Hugging Face model references in configs, unpinned Git dependencies, missing lockfiles, unpinned Docker images, remote install scripts, optional generic dependency pin checks, `pip-audit` results normalized into Ceres findings; `gitleaks` only when explicitly enabled |
| AI-BOM      | warns when models/datasets are present but no `ai-bom.json` exists |

Full docs:

- [Docs index](docs/index.md)
- [Rule catalog](docs/rules.md)
- [Model security and tensor scanning](docs/model-security.md)

Ceres **never imports model files**. Model artifacts are inspected statically
(pickle opcode decoding only, no `__reduce__` execution) with a 64 MB hard cap.

## Install

```bash
pip install ceres-scanner
# or, from this repo:
pip install -e .
```

Optional integrations: install [`pip-audit`](https://pypi.org/project/pip-audit/)
or, if you explicitly want generic secret scanning inside Ceres,
[`gitleaks`](https://github.com/gitleaks/gitleaks) on `PATH`. Ceres detects
enabled tools and folds their findings into the same report. If policy
enables an external scanner but it is missing, Ceres emits a low-severity
`ceres.supplychain.scanner_unavailable` finding so CI does not silently skip coverage.

## Quick start

```bash
ceres init                       # writes ceres.yml policy
ceres scan .                     # human-readable scan
ceres scan . --sarif-out out.sarif --json-out out.json
ceres baseline .                 # snapshot dataset+model+tool metadata -> .ceres/baseline.json
ceres bom . --out ai-bom.json    # Ceres AI-BOM
ceres list-rules                 # show known rule IDs
```

`scan` exits non-zero when findings at gated severities are present (defaults:
`critical` and `high` fail; `medium` warns).

## Example Use Case

A typical Ceres use case is reviewing a pull request for an AI support agent.
The PR changes model loading code, adds a new RAG document, updates a training
dataset, and touches dependencies.

```bash
ceres scan . --json-out ceres-report.json --sarif-out ceres.sarif
```

Example findings:

```text
CRITICAL  ceres.model.loader.remote_code_enabled
          src/app.py:10
          Model loader uses trust_remote_code=True.

CRITICAL  ceres.model.artifact.pickle_format
          models/final.pkl
          Pickle-based model artifact may execute code during deserialization.

HIGH      ceres.rag.instruction.ignore_context
          rag/vendor_policy.md:5
          RAG document contains instruction-like text.

HIGH      ceres.dataset.hash_drift
          data/train.csv
          Dataset hash differs from manifest declaration.
```

For a local demo from this repository:

```bash
ceres scan examples/vulnerable-ai-repo
ceres scan examples/vulnerable-ai-repo \
  --json-out examples/vulnerable-ai-repo/ceres-report.json \
  --sarif-out examples/vulnerable-ai-repo/ceres.sarif
ceres bom examples/vulnerable-ai-repo
ceres baseline examples/vulnerable-ai-repo
```

The vulnerable example is expected to fail. The clean example should pass:

```bash
ceres scan examples/clean-ai-repo
```

For real-world regression testing, run the seeded corpus harness. It copies or
clones AI repos, injects known-bad model/RAG/agent/data/supply-chain changes,
and fails if the expected rules do not fire:

```bash
python scripts/real_world_check.py \
  --corpus examples/real-world-corpus.yml \
  --workdir /tmp/ceres-real-world \
  --json-out /tmp/ceres-real-world/report.json
```

## Policy

`ceres.yml` controls gates, allowlists, and waivers. The defaults are
opinionated: `pickle` formats are blocked, `trust_remote_code` is denied, and
generic secret scanning is off by default so Ceres stays focused on AI-model and
AI-system risk.

```yaml
severity_gate:
  critical: fail
  high: fail
  medium: warn
  low: info

model_policy:
  allowed_formats: [safetensors, onnx, gguf]
  blocked_formats: [pkl, pickle]
  require_revision_pin: true
  allow_trust_remote_code: false

waivers:
  - rule_id: ceres.model.loader.remote_code_enabled
    file: src/research_loader.py
    reason: "Research-only script, not shipped"
    expires: "2026-12-01"
    approved_by: "security-team"
```

Expired waivers stop suppressing findings *and* are surfaced as a
`ceres.policy.waiver_expired` finding so they don't quietly rot.

## Baselines

```bash
ceres baseline .
git add .ceres/baseline.json
```

Once a baseline exists, Ceres compares dataset fingerprints (row count, duplicate
rate, label distribution, top trigrams), model/tokenizer state, and tool
metadata descriptions against it. Drift beyond policy thresholds becomes a
finding.

## Model Layer Scanning

Ceres should scan model layers and tensors for **poisoning indicators**, but it
should not claim that static layer inspection can prove a layer is poisoned.
Backdoors can be subtle and may only show up under specific triggers or runtime
behavior.

Ceres currently performs safe `.safetensors` tensor baseline checks without
importing model code or loading tensors into memory. It parses the safetensors
header, records tensor names, dtypes, shapes, offsets, SHA-256 hashes, and
compact numeric stats in the baseline, then compares future scans against that
baseline.

Implemented static checks:

- per-tensor SHA-256 hashes compared with a known-good baseline
- unexpected layer names, missing layers, added layers, or shape changes
- dtype changes
- NaN/Inf values and configured absolute-value range anomalies
- L2 norm drift and sparsity drift compared with baseline
- LoRA adapter metadata changes such as base model mismatch
- tokenizer, special-token, and chat-template changes that can hide behavior
  shifts outside obvious weight tensors

Planned checks:

- cross-layer outlier scoring for tensor families with similar roles
- ONNX/GGUF metadata and graph-level inspection

Good finding wording:

```text
HIGH ceres.model.tensor.norm_drift
models/adapter.safetensors
Layer "lm_head.weight" changed shape and has unusually large norm drift compared
with baseline.
```

Recommended policy: use layer/tensor scanning as a baseline-diff and anomaly
detector, then combine it with provenance, signatures, dataset checks, and
dynamic evaluation before making a poisoning claim.

See [Model security and tensor scanning](docs/model-security.md) for the
implemented model rules, baseline format, and policy knobs.

## CI

```yaml
# .github/workflows/ceres.yml
name: Ceres
on: [pull_request, push]
jobs:
  ceres:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install ceres-scanner
      - run: ceres scan . --sarif-out ceres.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: ceres.sarif }
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ceres
        name: Ceres AI security scanner
        entry: ceres scan . --policy ceres.yml
        language: system
        pass_filenames: false
```

## Status

Ceres is a young project. The MVP covers static rules for code, models, data,
RAG, prompts, and supply chain, plus AI-BOM and baselines. Dynamic red-team and
fuzz testing live downstream of `garak` / `promptfoo` / `PyRIT` and are not in
scope here.

See `examples/vulnerable-ai-repo/` for an example that trips most rules and
`examples/clean-ai-repo/` for a quiet baseline.
