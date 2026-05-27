# Model Security

Ceres scans model artifacts statically. It does not import model code, call
`torch.load`, instantiate transformer classes, or execute artifact contents.

The current deepest tensor inspection is for `.safetensors` because the format
has a simple static layout: header metadata followed by tensor byte ranges.
Ceres parses that layout directly and reads tensor bytes in bounded chunks.
For `.gguf` and `.onnx`, Ceres performs static metadata and structure
inspection without loading weights into a runtime.

## What Is Checked

```text
artifact format
  block pickle-backed formats, warn on PyTorch checkpoint formats, enforce
  allowed model artifact formats

artifact provenance
  require adjacent source/provenance metadata unless policy disables it; compare
  model file SHA-256 against baseline when present

safetensors structure
  validate header size, JSON shape, tensor dtype/shape/offset metadata, byte
  lengths, contiguous coverage of the tensor buffer

GGUF metadata
  validate the GGUF header, metadata table, tensor inventory, architecture
  metadata, and baseline drift for model identity / tensor count

ONNX metadata
  parse bounded protobuf metadata for IR version, producer, opsets, graph name,
  metadata properties, node count, and operator type counts

tensor and layer inventory
  track tensor names, dtypes, shapes, byte lengths, offsets, and per-tensor
  SHA-256 hashes

tensor numeric stats
  count values, finite values, NaNs, infinities, zeros, min, max, mean, L2 norm,
  and zero ratio for supported numeric dtypes

tokenizer / adapter metadata
  compare special tokens, chat templates, and LoRA base model metadata against
  baseline
```

## Baseline Flow

```bash
ceres baseline .
git add .ceres/baseline.json
ceres scan . --baseline .ceres/baseline.json
```

For `.safetensors`, baseline entries include:

```json
{
  "models/adapter.safetensors": {
    "sha256": "...",
    "format": "safetensors",
    "tensor_count": 2,
    "total_tensor_bytes": 1234,
    "header_bytes": 256,
    "metadata": {},
    "tensors": {
      "model.layers.0.self_attn.q_proj.weight": {
        "dtype": "F32",
        "shape": [32, 32],
        "offsets": [0, 4096],
        "byte_length": 4096,
        "sha256": "...",
        "stats": {
          "count": 1024,
          "finite_count": 1024,
          "nan_count": 0,
          "inf_count": 0,
          "zero_count": 12,
          "min": -0.14,
          "max": 0.13,
          "mean": 0.001,
          "l2_norm": 1.97,
          "zero_ratio": 0.01171875
        }
      }
    }
  }
}
```

For `.gguf` and `.onnx`, baseline entries include static metadata summaries
instead of tensor values. GGUF entries include metadata keys, tensor inventory,
metadata hash, and tensor-name hash. ONNX entries include model metadata,
opset imports, graph name, node count, operator counts, and stable hashes for
metadata/operator summaries.

## Model Rule IDs

### Model Loading Code

| Rule ID | Name | Default severity | What it catches |
|---|---|---:|---|
| `ceres.model.loader.remote_code_enabled` | Remote model code enabled | Critical | Model loader uses `trust_remote_code=True` while policy disallows it. |
| `ceres.model.loader.revision_unpinned` | Unpinned model loader revision | High | `from_pretrained(...)` call has no pinned model revision. |
| `ceres.model.loader.torch_unsafe_load` | Unsafe torch load | High | `torch.load(...)` is called without `weights_only=True`. |
| `ceres.model.loader.pickle_deserialize` | Pickle deserialization in code | High | Python code calls `pickle.load`, `pickle.loads`, or `pickle.Unpickler`. |
| `ceres.model.loader.joblib_deserialize` | Joblib deserialization in code | High | Python code calls `joblib.load(...)`, which is pickle-backed. |

### Model Artifacts And Metadata

| Rule ID | Name | Default severity | What it catches |
|---|---|---:|---|
| `ceres.model.artifact.format_not_allowed` | Disallowed model format | High | Model artifact extension/format is not in `model_policy.allowed_formats`. |
| `ceres.model.artifact.hash_drift` | Model artifact hash drift | High | Model file SHA-256 differs from the baseline entry. |
| `ceres.model.artifact.pickle_format` | Pickle model artifact | Critical | `.pkl`, `.pickle`, or equivalent pickle-backed model artifact is present. |
| `ceres.model.artifact.pickle_opcode_risk` | Suspicious pickle opcodes | Critical | Static pickle scan detects risky globals/opcodes indicating unsafe deserialization risk. |
| `ceres.model.artifact.pickle_parse_error` | Pickle parse error | High | Static pickle scan could not fully parse a pickle-backed artifact, but no dangerous opcode/global was confirmed. |
| `ceres.model.artifact.prefer_safetensors` | Prefer safetensors | Medium | PyTorch checkpoint-like artifact is present and should be migrated to safetensors where practical. |
| `ceres.model.artifact.source_missing_or_unapproved` | Missing or unapproved model source | High | Model artifact/config lacks source metadata or references a source outside `approved_model_sources`. |
| `ceres.model.config.revision_unpinned` | Unpinned configured model reference | High | YAML/JSON config references a Hugging Face-style model without a pinned revision. |
| `ceres.model.safetensors.header_invalid` | Invalid safetensors header | High | Header is truncated, not JSON, malformed, has invalid tensor entries, invalid offsets, or inconsistent tensor byte lengths. |
| `ceres.model.safetensors.header_oversized` | Oversized safetensors header | High | Header length exceeds `max_safetensors_header_bytes`. |
| `ceres.model.gguf.header_invalid` | Invalid GGUF header | High | GGUF file is truncated, has invalid magic/version, malformed metadata, invalid tensor metadata, or unsupported value types. |
| `ceres.model.gguf.metadata_oversized` | Oversized GGUF metadata | High | GGUF metadata strings, arrays, entry counts, tensor counts, or total metadata bytes exceed scanner limits. |
| `ceres.model.gguf.architecture_drift` | GGUF architecture drift | High | `general.architecture` changed compared with baseline. |
| `ceres.model.gguf.metadata_drift` | GGUF metadata drift | Medium | GGUF metadata digest changed compared with baseline. |
| `ceres.model.gguf.tensor_count_drift` | GGUF tensor count drift | Medium | GGUF tensor count changed compared with baseline. |
| `ceres.model.onnx.header_invalid` | Invalid ONNX protobuf | High | ONNX protobuf is empty, truncated, malformed, or lacks recognizable model metadata. |
| `ceres.model.onnx.metadata_oversized` | Oversized ONNX metadata | High | ONNX strings, metadata properties, graph nodes, or operator type counts exceed scanner limits. |
| `ceres.model.onnx.metadata_drift` | ONNX metadata drift | Medium | ONNX model identity/producer/graph/metadata summary changed compared with baseline. |
| `ceres.model.onnx.opset_drift` | ONNX opset drift | High | ONNX opset imports changed compared with baseline. |
| `ceres.model.onnx.operator_drift` | ONNX operator drift | Medium | ONNX node/operator summary changed compared with baseline. |
| `ceres.model.tensor.added` | Tensor added | Medium | Tensor exists in current model but not in baseline. |
| `ceres.model.tensor.removed` | Tensor removed | High | Tensor existed in baseline but is missing now. |
| `ceres.model.tensor.shape_changed` | Tensor shape changed | High | Tensor shape differs from baseline. |
| `ceres.model.tensor.dtype_changed` | Tensor dtype changed | Medium | Tensor dtype differs from baseline. |
| `ceres.model.tensor.hash_drift` | Tensor hash drift | Medium | Tensor bytes changed while the tensor still exists and has a baseline hash. |
| `ceres.model.tensor.nan_or_inf` | Tensor NaN/Inf values | High | Tensor numeric stats contain NaN or infinity values. |
| `ceres.model.tensor.norm_drift` | Tensor norm drift | Medium | Tensor L2 norm changed beyond `tensor_norm_drift_ratio` compared with baseline. |
| `ceres.model.tensor.sparsity_drift` | Tensor sparsity drift | Medium | Tensor zero ratio changed beyond `tensor_sparsity_drift_ratio` compared with baseline. |
| `ceres.model.tensor.range_anomaly` | Tensor range anomaly | Medium | Tensor min/max absolute value exceeds `max_tensor_abs_value`. |
| `ceres.model.tensor.suspicious_name` | Suspicious tensor name | Low | Tensor name contains configured marker text such as `backdoor`, `trigger`, or `jailbreak`. |
| `ceres.model.tokenizer.special_token_drift` | Special token drift | High | Special token files gained new tokens compared with baseline. |
| `ceres.model.chat_template.drift` | Chat template drift | High | `tokenizer_config.json` chat template differs from baseline. |
| `ceres.model.lora.base_model_drift` | LoRA base model drift | High | `adapter_config.json` base model changed compared with baseline. |

## Policy Knobs

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
  tensor_hash_block_size: 1048576
  tensor_stat_block_size: 1048576
  tensor_norm_drift_ratio: 0.50
  tensor_sparsity_drift_ratio: 0.20
  max_tensor_abs_value: 1000000.0
  max_gguf_metadata_bytes: 67108864
  max_gguf_string_bytes: 1048576
  max_onnx_string_bytes: 1048576
  max_onnx_nodes: 200000
  suspicious_tensor_name_patterns:
    - backdoor
    - trigger
    - override
    - jailbreak
    - malicious
    - admin
```

## Limitations

Static model inspection is a poisoning indicator, not a proof of poisoning.
Backdoors can be subtle, distributed across many tensors, or activated only by
specific runtime prompts/triggers. Treat tensor findings as a review gate:
confirm provenance, compare training changes, inspect dataset changes, and run
dynamic evaluation where the risk justifies it.

Current tensor stats are implemented for numeric safetensors dtypes that can be
decoded safely with the standard library. FP8 values are structurally validated
but are not numerically profiled yet. GGUF and ONNX scanning is metadata-only;
it does not validate full graph semantics or inspect tensor payload values.
