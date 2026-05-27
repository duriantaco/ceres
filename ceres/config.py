from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


GateAction = Literal["fail", "warn", "info", "ignore"]


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyError(ValueError):
    pass


class SeverityGate(StrictBaseModel):
    critical: GateAction = "fail"
    high: GateAction = "fail"
    medium: GateAction = "warn"
    low: GateAction = "info"
    info: GateAction = "info"

    def as_dict(self) -> dict[str, str]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
        }


class FrameworkMapping(StrictBaseModel):
    include: list[str] = Field(
        default_factory=lambda: ["owasp_llm_2025", "owasp_ml_top10", "mitre_atlas", "nist_aml"]
    )


class ModelPolicy(StrictBaseModel):
    allowed_formats: list[str] = Field(default_factory=lambda: ["safetensors", "onnx", "gguf"])
    blocked_formats: list[str] = Field(default_factory=lambda: ["pkl", "pickle"])
    require_sha256: bool = True
    require_known_source: bool = True
    require_revision_pin: bool = True
    allow_trust_remote_code: bool = False
    approved_model_sources: list[str] = Field(default_factory=list)
    scan_safetensors_tensors: bool = True
    max_safetensors_header_bytes: int = 10 * 1024 * 1024
    max_tensor_hash_bytes: int = 1024 * 1024 * 1024
    max_tensor_stat_bytes: int = 256 * 1024 * 1024
    tensor_hash_block_size: int = 1024 * 1024
    tensor_stat_block_size: int = 1024 * 1024
    tensor_norm_drift_ratio: float = 0.50
    tensor_sparsity_drift_ratio: float = 0.20
    max_tensor_abs_value: float = 1_000_000.0
    max_gguf_metadata_bytes: int = 64 * 1024 * 1024
    max_gguf_string_bytes: int = 1024 * 1024
    max_onnx_string_bytes: int = 1024 * 1024
    max_onnx_nodes: int = 200_000
    suspicious_tensor_name_patterns: list[str] = Field(
        default_factory=lambda: [
            "backdoor",
            "trigger",
            "override",
            "jailbreak",
            "malicious",
            "admin",
        ]
    )


class DataPolicy(StrictBaseModel):
    require_manifest: bool = True
    require_hashes: bool = True
    require_owner: bool = True
    allowed_sources: list[str] = Field(default_factory=list)
    max_duplicate_rate: float = 0.05
    max_new_source_ratio: float = 0.02
    max_label_jsd: float = 0.10
    scan_for_prompt_injection: bool = True
    scan_for_secrets: bool = False


class RagPolicy(StrictBaseModel):
    require_source_metadata: bool = False
    require_doc_owner: bool = False
    block_instruction_like_content: bool = True
    scan_hidden_html: bool = True
    require_retrieval_filter: bool = True
    require_ingest_sanitizer: bool = True
    allowed_domains: list[str] = Field(default_factory=list)
    include_paths: list[str] = Field(default_factory=list)


class EvalPolicy(StrictBaseModel):
    require_safety_eval: bool = True
    require_regression_eval: bool = True
    block_disabled_safety_filters: bool = True
    min_safety_score: float = 0.90
    max_generation_temperature: float = 1.0


class CodePolicy(StrictBaseModel):
    block_pickle_load: bool = True
    block_unsafe_torch_load: bool = True
    block_eval_exec: bool = True
    block_trust_remote_code: bool = True
    require_tool_allowlist: bool = True
    scan_tool_descriptions: bool = True
    scan_inline_secrets: bool = False


class DependencyPolicy(StrictBaseModel):
    run_pip_audit: bool = True
    run_osv_scanner: bool = False
    run_gitleaks: bool = False
    require_lockfile: bool = False
    scan_unpinned_dependencies: bool = False
    block_critical_cves: bool = True


class OutputPolicy(StrictBaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    sarif: bool = False
    json_: bool = Field(False, alias="json")
    markdown_summary: bool = False


class CleanBudgets(StrictBaseModel):
    total: int | None = None
    critical: int | None = None
    high: int | None = None
    medium: int | None = None
    low: int | None = None
    analyzer_failures: int = 0


class RealWorldValidationPolicy(StrictBaseModel):
    clean_budgets: CleanBudgets = Field(default_factory=CleanBudgets)


class Policy(StrictBaseModel):
    version: int = 1
    mode: Literal["dev", "ci"] = "ci"
    severity_gate: SeverityGate = Field(default_factory=SeverityGate)
    framework_mapping: FrameworkMapping = Field(default_factory=FrameworkMapping)
    model_policy: ModelPolicy = Field(default_factory=ModelPolicy)
    data_policy: DataPolicy = Field(default_factory=DataPolicy)
    rag_policy: RagPolicy = Field(default_factory=RagPolicy)
    eval_policy: EvalPolicy = Field(default_factory=EvalPolicy)
    code_policy: CodePolicy = Field(default_factory=CodePolicy)
    dependency_policy: DependencyPolicy = Field(default_factory=DependencyPolicy)
    output: OutputPolicy = Field(default_factory=OutputPolicy)
    real_world_validation: RealWorldValidationPolicy = Field(default_factory=RealWorldValidationPolicy)
    waivers: list[dict[str, Any]] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None) -> "Policy":
        if path is None:
            return cls()
        if not path.exists():
            raise PolicyError(f"{path}: policy file not found")
        try:
            with path.open() as f:
                raw = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise PolicyError(f"{path}: invalid YAML: {e}") from e
        try:
            return cls.model_validate(raw)
        except Exception as e:  # noqa: BLE001
            raise PolicyError(f"{path}: invalid policy: {e}") from e


DEFAULT_POLICY_YAML = """\
version: 1
mode: ci

severity_gate:
  critical: fail
  high: fail
  medium: warn
  low: info

framework_mapping:
  include:
    - owasp_llm_2025
    - owasp_ml_top10
    - mitre_atlas
    - nist_aml

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

data_policy:
  require_manifest: true
  require_hashes: true
  require_owner: true
  allowed_sources: []
  max_duplicate_rate: 0.05
  max_new_source_ratio: 0.02
  max_label_jsd: 0.10
  scan_for_prompt_injection: true
  scan_for_secrets: false

rag_policy:
  require_source_metadata: false
  require_doc_owner: false
  block_instruction_like_content: true
  scan_hidden_html: true
  require_retrieval_filter: true
  require_ingest_sanitizer: true
  allowed_domains: []
  include_paths: []

eval_policy:
  require_safety_eval: true
  require_regression_eval: true
  block_disabled_safety_filters: true
  min_safety_score: 0.90
  max_generation_temperature: 1.0

code_policy:
  block_pickle_load: true
  block_unsafe_torch_load: true
  block_eval_exec: true
  block_trust_remote_code: true
  require_tool_allowlist: true
  scan_tool_descriptions: true
  scan_inline_secrets: false

dependency_policy:
  run_pip_audit: true
  run_osv_scanner: false
  run_gitleaks: false
  require_lockfile: false
  scan_unpinned_dependencies: false
  block_critical_cves: true

output:
  sarif: false
  json: false
  markdown_summary: false

real_world_validation:
  clean_budgets:
    total:
    critical:
    high:
    medium:
    low:
    analyzer_failures: 0

# Example waiver:
# waivers:
#   - rule_id: ceres.model.loader.remote_code_enabled
#     file: src/research_loader.py
#     reason: "Research-only script, not shipped"
#     expires: "2026-12-01"
#     approved_by: "security-team"
waivers: []
"""
