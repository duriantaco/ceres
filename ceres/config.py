from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


GateAction = Literal["fail", "warn", "info", "ignore"]


class SeverityGate(BaseModel):
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


class FrameworkMapping(BaseModel):
    include: list[str] = Field(
        default_factory=lambda: ["owasp_llm_2025", "owasp_ml_top10", "mitre_atlas", "nist_aml"]
    )


class ModelPolicy(BaseModel):
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


class DataPolicy(BaseModel):
    require_manifest: bool = True
    require_hashes: bool = True
    require_owner: bool = True
    allowed_sources: list[str] = Field(default_factory=list)
    max_duplicate_rate: float = 0.05
    max_new_source_ratio: float = 0.02
    max_label_jsd: float = 0.10
    scan_for_prompt_injection: bool = True
    scan_for_secrets: bool = False


class RagPolicy(BaseModel):
    require_source_metadata: bool = False
    require_doc_owner: bool = False
    block_instruction_like_content: bool = True
    scan_hidden_html: bool = True
    allowed_domains: list[str] = Field(default_factory=list)


class CodePolicy(BaseModel):
    block_pickle_load: bool = True
    block_unsafe_torch_load: bool = True
    block_eval_exec: bool = True
    block_trust_remote_code: bool = True
    require_tool_allowlist: bool = True
    scan_tool_descriptions: bool = True
    scan_inline_secrets: bool = False


class DependencyPolicy(BaseModel):
    run_pip_audit: bool = True
    run_osv_scanner: bool = False
    run_gitleaks: bool = False
    require_lockfile: bool = False
    block_critical_cves: bool = True


class OutputPolicy(BaseModel):
    model_config = {"protected_namespaces": ()}

    sarif: bool = False
    json_: bool = Field(False, alias="json")
    markdown_summary: bool = False


class Policy(BaseModel):
    version: int = 1
    mode: Literal["dev", "ci"] = "ci"
    severity_gate: SeverityGate = Field(default_factory=SeverityGate)
    framework_mapping: FrameworkMapping = Field(default_factory=FrameworkMapping)
    model_policy: ModelPolicy = Field(default_factory=ModelPolicy)
    data_policy: DataPolicy = Field(default_factory=DataPolicy)
    rag_policy: RagPolicy = Field(default_factory=RagPolicy)
    code_policy: CodePolicy = Field(default_factory=CodePolicy)
    dependency_policy: DependencyPolicy = Field(default_factory=DependencyPolicy)
    output: OutputPolicy = Field(default_factory=OutputPolicy)
    waivers: list[dict[str, Any]] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None) -> "Policy":
        if path is None or not path.exists():
            return cls()
        with path.open() as f:
            raw = yaml.safe_load(f) or {}
        return cls.model_validate(raw)


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
  allowed_domains: []

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
  block_critical_cves: true

output:
  sarif: false
  json: false
  markdown_summary: false

# Example waiver:
# waivers:
#   - rule_id: ceres.model.loader.remote_code_enabled
#     file: src/research_loader.py
#     reason: "Research-only script, not shipped"
#     expires: "2026-12-01"
#     approved_by: "security-team"
waivers: []
"""
