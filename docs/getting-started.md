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
ceres scan . --diff-base origin/main
```

By default, `critical` and `high` findings fail the scan. `medium` findings warn.

Use `--diff-base` in pull-request workflows to show only findings on files or
lines changed since a git base ref. Ceres still scans with full repository
context, then filters out pre-existing findings outside the diff.

## Read Scan Output

The CLI is meant to answer three questions after a scan:

- did this repo pass the configured severity gate?
- what AI system area is risky: model, data, eval, RAG, prompt, agent, deps,
  AI-BOM, or policy?
- what should I fix or verify next?

When findings exist, the report includes:

| Section | Meaning |
|---|---|
| `Ceres AI Security Scan` | Overall pass/fail, total findings, gated findings, and severity mix. |
| `Risk Areas` | Findings grouped by AI system layer so reviewers can see whether the risk is model supply chain, RAG, agent tooling, data, eval, or another area. |
| `What Ceres Caught First` | The highest-priority findings with the rule, problem, why it matters, next step, and evidence. |
| `Additional Findings` | Remaining findings with the problem and recommended fix. |
| `What To Do Next` | The practical workflow: fix or waive gated findings, update provenance/baselines when changes are intentional, then rerun the scan. |

In diff mode, the summary also shows the base ref, compare commit, changed-file
count, and how many full-scan findings were retained after diff filtering.

Use `--json-out` and `--sarif-out` when CI or another tool needs the same
findings in machine-readable form.

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
