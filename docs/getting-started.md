# Install And Run

## Install

From this repository:

```bash
pip install -e .
```

Optional integrations:

```bash
pip install pip-audit
```

`gitleaks` integration is available but off by default. Use Skylos for generic
secret and leak scanning unless you deliberately opt into the adapter.

## Initialize Policy

```bash
ceres init
```

This writes `ceres.yml` with conservative defaults:

```yaml
model_policy:
  allowed_formats: [safetensors, onnx, gguf]
  blocked_formats: [pkl, pickle]
  require_known_source: true
  require_revision_pin: true
  allow_trust_remote_code: false

code_policy:
  scan_inline_secrets: false

dependency_policy:
  run_pip_audit: true
  run_gitleaks: false
  scan_unpinned_dependencies: false
```

## Create Baseline

```bash
ceres baseline .
git add .ceres/baseline.json
```

The baseline records model hashes, safetensors tensor metadata/stats, tokenizer
state, dataset fingerprints, and RAG inventory. Future scans compare current
state against this known-good snapshot.

## Run Scan

```bash
ceres scan .
ceres scan . --json-out ceres-report.json --sarif-out ceres.sarif
```

By default, `critical` and `high` findings fail the scan. `medium` findings warn.

## Generate AI-BOM

```bash
ceres bom . --out ai-bom.json
git add ai-bom.json
```

The AI-BOM uses a Ceres-owned JSON envelope and lists model, dataset, and prompt components.

## List Rules

```bash
ceres list-rules
```

See [Rule Catalog](rules.md) for rule names, default severities, and trigger
conditions.
