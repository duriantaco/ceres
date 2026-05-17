# Policy

Ceres policy lives in `ceres.yml`. It controls scanner behavior, severity gates,
source allowlists, model integrity limits, optional integrations, and waivers.

## Severity Gates

```yaml
severity_gate:
  critical: fail
  high: fail
  medium: warn
  low: info
```

The CLI exits non-zero when a finding reaches a severity configured as `fail`.

## Model Policy

```yaml
model_policy:
  allowed_formats: [safetensors, onnx, gguf]
  blocked_formats: [pkl, pickle]
  require_sha256: true
  require_known_source: true
  require_revision_pin: true
  allow_trust_remote_code: false
  approved_model_sources: []
  scan_safetensors_tensors: true
  max_safetensors_header_bytes: 10485760
  max_tensor_hash_bytes: 1073741824
  max_tensor_stat_bytes: 268435456
  tensor_norm_drift_ratio: 0.50
  tensor_sparsity_drift_ratio: 0.20
  max_tensor_abs_value: 1000000.0
```

Use `approved_model_sources` to restrict model configs and adjacent provenance
metadata to reviewed registries or buckets.

## Data And RAG Policy

```yaml
data_policy:
  require_manifest: true
  require_hashes: true
  require_owner: true
  allowed_sources: []
  max_duplicate_rate: 0.05
  max_label_jsd: 0.10

rag_policy:
  require_source_metadata: false
  require_doc_owner: false
  block_instruction_like_content: true
  scan_hidden_html: true
  allowed_domains: []
```

Set `allowed_sources` and `allowed_domains` in CI to keep data/RAG changes
reviewable.

## Secret Scanning Boundary

```yaml
code_policy:
  scan_inline_secrets: false

dependency_policy:
  run_gitleaks: false
```

These defaults are intentional. Ceres is focused on AI pre-production security.
Use Skylos for generic secret and leak scanning.

## Waivers

```yaml
waivers:
  - rule_id: ceres.model.loader.remote_code_enabled
    file: src/research_loader.py
    reason: "Research-only script, not shipped"
    expires: "2026-12-01"
    approved_by: "security-team"
```

Expired waivers no longer suppress findings and emit
`ceres.policy.waiver_expired`.
