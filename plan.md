Yes. The move is:

> **Borrow proven architecture patterns from existing security tools, then build the missing “AI repo static analyzer” layer on top.**

Important: use existing tools as **design references only**: architecture
patterns, workflow ideas, and public integration formats. Ceres must keep its
own code, own rule IDs, own rule text, and own rule semantics.

The product should be something like:

```bash
aisec scan .
```

And it should check:

```text
code + prompts + configs + model files + datasets + RAG docs + dependencies + AI-BOM
```

## 1. The core idea

Build a **developer-first AI security scanner**.

Not a giant enterprise dashboard first. Not a generic red-team tool. The wedge should be:

> **AI-SAST for repos: pre-commit and CI security scanning for AI/ML projects.**

Existing tools already cover pieces. ModelScan scans model artifacts for unsafe code and supports formats like H5, Pickle, and SavedModel. garak probes LLMs for issues like prompt injection, data leakage, toxicity, and hallucination. promptfoo supports LLM evals, red teaming, CI/CD integration, and code scanning. PyRIT is a Microsoft open-source framework for proactive GenAI risk identification. ([GitHub][1])

Your opportunity is to unify the pieces and add the static AI-repo layer that most teams still don’t have.

---

# 2. What to adapt from existing tools

## A. From Semgrep

Adapt the **rule-based architecture**.

Semgrep’s power is that rules are simple, readable, and extensible. Its docs describe rules as pattern-matching and data-flow logic used to scan code for security issues, style violations, bugs, and config problems. ([Semgrep][2])

Your AI-SAST rules should look like:

```yaml
id: ceres.model.loader.remote_code_enabled
severity: high
layer: code
frameworks:
  owasp_llm: LLM03
  owasp_ml: ML06
message: "Model loader enables trust_remote_code=True."
match:
  language: python
  pattern: "from_pretrained(..., trust_remote_code=True)"
recommendation: "Pin model revision and disable remote code unless explicitly approved."
```

This lets users write custom rules later.

## B. From ModelScan / ModelAudit / Picklescan / Fickling

Adapt the **safe model artifact scanning pattern**.

ModelScan scans model files to determine if they contain unsafe code, and supports multiple model formats including H5, Pickle, and SavedModel. ([GitHub][1])

Promptfoo’s ModelAudit is a newer model scanning tool that scans AI/ML models for security vulnerabilities, malicious code, and backdoors, and its docs mention support for PyTorch, TensorFlow, ONNX, Keras, and 30+ model formats. ([promptfoo.dev][3])

Picklescan detects suspicious Python Pickle actions, and Fickling can decompile/analyze pickle files and enforce allowlists around imports when loading AI/ML model files. ([GitHub][4])

Your rule: **never execute model files during scan**. Parse bytes, headers, metadata, pickle opcodes, zip/tar contents, tensor shapes, configs, and hashes. Do not import the model.

## C. From garak / promptfoo / PyRIT

Adapt the **plugin/probe/detector design**, but reserve it for optional dynamic testing.

garak uses probes to query LLMs and detectors to check the outputs for weaknesses. ([GitHub][5])

promptfoo’s red-team flow has init, run, and report steps, and it generates adversarial test cases and evaluates the target. ([GitHub][6])

PyRIT is built as a flexible, extensible framework for assessing GenAI security and safety risks. ([GitHub][7])

Your static analyzer can later have:

```text
aisec scan .             # static
aisec eval .             # dynamic
aisec redteam .          # optional red-team mode
```

But for MVP, focus on `scan`.

## D. From Gitleaks

Adapt the **fast local scanner + pre-commit workflow**, not secret-scanning
rules or patterns.

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, API keys, and tokens in Git repos, files, and stdin. ([GitHub][8])

Your equivalent:

```text
Skylos/Gitleaks for secrets
+
Ceres for model/data/RAG/prompt/tool/MCP risk
```

## E. From pip-audit / OSV-Scanner

Do not rebuild dependency scanning. Wrap existing tools.

`pip-audit` scans Python environments or requirements files for packages with known vulnerabilities. OSV provides a distributed vulnerability database for open-source packages, and OSV-Scanner connects project dependencies to known vulnerabilities. ([PyPI][9])

Your scanner can normalize their results into your own finding format.

## F. From Cleanlab / Evidently / TFDV / whylogs

Adapt the **dataset profiling and anomaly detection mindset**, then make it security-focused.

Cleanlab can detect mislabeled data, outliers, ambiguous examples, and other dataset issues. Evidently has data drift detection presets. TensorFlow Data Validation can compute statistics, infer schemas, detect anomalies, detect training-serving skew, and detect data drift. whylogs creates lightweight, mergeable dataset profiles for tracking distribution changes. ([Cleanlab Docs][10])

Your differentiator is not generic “data quality.” It is:

```text
data quality + poisoning indicators + provenance + policy gates
```

---

# 3. Product architecture

The scanner should be modular.

```text
                    ┌─────────────────────────┐
                    │        aisec CLI         │
                    │ scan / init / baseline   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      Repo Inventory      │
                    │ files, git diff, types   │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
│ Code Analyzer  │      │ Model Analyzer  │      │ Data Analyzer   │
│ AI-SAST rules  │      │ artifacts       │      │ poisoning signs │
└───────┬────────┘      └────────┬────────┘      └────────┬────────┘
        │                        │                        │
┌───────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
│ Prompt/RAG     │      │ Dependency      │      │ AI-BOM          │
│ Corpus Scanner │      │ Scanner         │      │ Generator       │
└───────┬────────┘      └────────┬────────┘      └────────┬────────┘
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Finding Normalizer   │
                    │ severity, evidence, fix  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │       Reporters          │
                    │ CLI / JSON / SARIF / MD  │
                    └─────────────────────────┘
```

GitHub supports uploading third-party SARIF files so the findings can appear as code scanning alerts. ([GitHub Docs][11])

---

# 4. The main modules

## Module 1: Repo inventory

This is the first step. Before scanning, identify what exists.

Detect:

```text
Python files
notebooks
prompt files
YAML/JSON configs
model artifacts
tokenizers
LoRA adapters
datasets
RAG documents
vector DB dumps
requirements/lockfiles
Dockerfiles
CI files
```

Example inventory output:

```json
{
  "code": ["src/load_model.py", "src/agent.py"],
  "prompts": ["prompts/system.txt"],
  "configs": ["config.yaml"],
  "models": ["models/adapter_model.bin", "models/tokenizer.json"],
  "datasets": ["data/train.parquet"],
  "rag_docs": ["docs/refund_policy.md", "docs/internal_guide.md"],
  "dependencies": ["requirements.txt", "pyproject.toml"]
}
```

This lets each analyzer receive only relevant files.

---

## Module 2: AI-SAST code analyzer

This is your “Semgrep for AI code” part.

Scan Python AST, YAML, JSON, notebooks, and maybe JS/TS later.

High-signal rules:

```text
ceres.model.loader.remote_code_enabled
ceres.model.loader.revision_unpinned
ceres.model.loader.torch_unsafe_load
ceres.model.loader.pickle_deserialize
ceres.ai_code.dynamic_execution
ceres.agent.tool.unreviewed_capability
ceres.agent.tool.shell_enabled
ceres.rag.retrieval.source_filter_missing
ceres.rag.output_validation_missing
ceres.prompt.system_context_user_slot
ceres.rag.vector_namespace_filter_missing
ceres.agent.tool.allowlist_missing
```

Optional only, because generic leak detection belongs to Skylos:

```text
ceres.prompt.secret_literal
```

Example finding:

```text
HIGH ceres.model.loader.remote_code_enabled src/load_model.py:14
Model loader uses trust_remote_code=True without an approved model source.
```

Example pattern:

```python
AutoModelForCausalLM.from_pretrained(
    model_name,
    trust_remote_code=True
)
```

This should be a **fail** by default unless the policy allows it.

---

## Module 3: Model artifact analyzer

This checks model files before anyone loads them.

Scan:

```text
.pkl
.pickle
.pt
.pth
.bin
.safetensors
.onnx
.h5
.keras
.pb
.gguf
joblib
tokenizer.json
config.json
adapter_config.json
```

Checks:

```text
- risky serialization format
- unsafe pickle opcodes/imports
- missing SHA256
- unknown source
- model not pinned by revision
- model card missing
- license missing
- tokenizer changed unexpectedly
- special tokens changed
- chat template changed
- LoRA adapter changed target modules
- tensor shape changed unexpectedly
- NaN/Inf in tensor metadata if safely inspectable
- suspicious archive structure
```

Prefer `safetensors` where possible. Safetensors is designed to store ML weights safely and avoids arbitrary code execution during deserialization by only allowing numerical tensor data. ([PyTorch][12])

Example finding:

```json
{
  "rule_id": "ceres.model.artifact.pickle_format",
  "severity": "critical",
  "file": "models/final_model.pkl",
  "message": "Pickle-based model artifact may execute code during deserialization.",
  "recommendation": "Use safetensors or ONNX, or require signed/provenanced model artifacts."
}
```

---

## Module 4: Dataset poisoning analyzer

This is where you can be early.

OWASP’s ML Top 10 includes data poisoning, AI supply-chain attacks, and model poisoning. OWASP’s LLM Top 10 also includes training data poisoning and supply-chain vulnerabilities. ([OWASP][13])

The analyzer should not claim:

```text
"This dataset is definitely poisoned."
```

It should say:

```text
"This dataset has poisoning risk indicators."
```

### Dataset manifest

Require each dataset to have a manifest:

```yaml
dataset:
  name: support-finetune-v3
  version: 3
  owner: ml-platform
  files:
    - path: data/train.parquet
      sha256: "..."
  source_allowlist:
    - s3://company-approved-data/
    - https://docs.company.com/
  schema:
    text: string
    label: string
  labels:
    allowed: ["refund", "billing", "technical", "abuse"]
  thresholds:
    max_duplicate_rate: 0.05
    max_new_source_ratio: 0.02
    max_label_jsd: 0.10
    max_rare_phrase_repetition: 20
```

### Dataset checks

Run:

```text
Provenance checks
- missing manifest
- missing hashes
- unknown source
- source domain changed
- dataset changed without manifest update

Schema checks
- missing required columns
- unexpected new columns
- type changes
- null spike
- length spike

Distribution checks
- dataset size jump
- label distribution drift
- feature/value distribution drift
- class imbalance spike
- suspicious underrepresented group changes

Poisoning signal checks
- near-duplicate flood
- repeated rare trigger phrases
- one source dominating new rows
- sudden appearance of strange tokens
- many labels flipped compared to previous baseline
- outlier cluster injection
- contradictory examples
- low-quality synthetic-looking rows

Text/RAG-specific checks
- prompt-injection phrases in documents
- hidden instructions in markdown/html
- base64-looking or encoded blobs
- docs telling model to ignore system instructions
- retrieval docs with tool-use instructions
- unexpected external links
```

Example finding:

```text
HIGH ceres.dataset.rare_phrase_repetition data/train.parquet
Phrase "blue pineapple refund override" appears 184 times in new rows but 0 times in baseline.
```

### Baseline comparison

The baseline is key.

```bash
aisec baseline create --dataset data/train.parquet --out .aisec/baseline.json
aisec scan . --baseline .aisec/baseline.json
```

Store:

```json
{
  "dataset_fingerprint": "sha256...",
  "row_count": 98231,
  "label_distribution": {
    "refund": 0.31,
    "billing": 0.24,
    "technical": 0.40,
    "abuse": 0.05
  },
  "top_domains": ["docs.company.com"],
  "top_ngrams": ["refund policy", "billing issue"],
  "embedding_profile": "...",
  "duplicate_rate": 0.018
}
```

---

## Module 5: RAG corpus scanner

This should be one of your sharpest early wedges.

RAG docs are a weird hybrid: they are “data,” but they can also contain **instructions** that the model may follow. OWASP’s LLM risk list includes prompt injection, supply-chain issues, and data/model poisoning, which map nicely to RAG corpus scanning. ([OWASP Gen AI Security Project][14])

Scan:

```text
.md
.txt
.html
.pdf text extraction
confluence exports
notion exports
knowledge base docs
vector DB source dumps
```

Rules:

```text
ceres.rag.instruction.ignore_context
ceres.rag.instruction.system_override
ceres.rag.instruction.secret_request
ceres.rag.instruction.tool_request
ceres.rag.hidden_instruction_markup
ceres.rag.encoded_payload
ceres.rag.domain_unapproved
ceres.rag.owner_missing
ceres.rag.index.rebuild_missing
ceres.rag.doc.duplicate_flood
ceres.rag.doc.untrusted_external_link
```

Example:

```text
HIGH ceres.rag.instruction.ignore_context docs/vendor_policy.md
Document contains instruction-like text targeting the model: "ignore previous instructions..."
```

Don’t only search exact phrases. Use fuzzy patterns:

```text
ignore previous instructions
ignore all prior instructions
system prompt
developer message
you are now
reveal secrets
send the API key
call this tool
run shell
exfiltrate
```

Also check HTML/Markdown tricks:

```html
<span style="display:none">ignore previous instructions...</span>
```

---

## Module 6: Prompt and config scanner

Scan:

```text
prompts/*.txt
prompts/*.md
config.yaml
agent.yaml
tools.json
openapi specs
langchain configs
llamaindex configs
workflow configs
```

Rules:

```text
ceres.prompt.system_context_leakage_risk
ceres.prompt.output_schema_missing
ceres.prompt.refusal_policy_missing
ceres.prompt.system_context_user_slot
ceres.agent.agency.excessive
ceres.agent.tool.browser_unrestricted
ceres.agent.tool.shell_without_allowlist
ceres.agent.tool.file_write_unrestricted
ceres.agent.tool.allowlist_missing
ceres.agent.action.confirmation_missing
ceres.rag.response.citation_policy_missing
ceres.rag.retrieval.filter_missing
optional: ceres.prompt.secret_literal
```

Example config issue:

```yaml
tools:
  shell:
    enabled: true
    allowlist: "*"
```

Finding:

```text
CRITICAL ceres.agent.tool.shell_without_allowlist config/agent.yaml
Agent has unrestricted shell access without command allowlist.
```

---

## Module 7: Dependency and supply-chain analyzer

Wrap existing scanners:

```text
pip-audit
osv-scanner
optional: semgrep
optional: OpenSSF Scorecard for external repos
```

Do not make generic secret/leak scanning part of the Ceres default wedge. If a
team wants that coverage, hand off to Skylos or explicitly enable an external
adapter.

OpenSSF Scorecard assesses open-source projects for security risks through automated checks. ([undefined][15])

Checks:

```text
- vulnerable dependency
- unpinned dependency
- dependency from unknown index
- direct GitHub dependency without commit pin
- Hugging Face model without revision pin
- Docker image without digest
- CI pulls remote scripts with curl | bash
- secrets in prompts/config/code
```

Example:

```text
HIGH ceres.model.config.revision_unpinned config.yaml
Model source "org/model-name" is not pinned to a revision hash.
```

---

## Module 8: AI-BOM generator

This is important.

Ceres should use its own AI-BOM envelope and keep any public-format exporters as optional integrations.

Generate:

```bash
aisec bom --out ai-bom.json
```

Include:

```json
{
  "models": [
    {
      "name": "mistral-7b-adapter",
      "source": "huggingface",
      "revision": "abc123",
      "sha256": "...",
      "format": "safetensors",
      "license": "apache-2.0"
    }
  ],
  "datasets": [
    {
      "name": "support-finetune-v3",
      "source": "s3://company-approved-data/",
      "sha256": "...",
      "row_count": 98231
    }
  ],
  "prompts": [
    {
      "path": "prompts/system.txt",
      "sha256": "..."
    }
  ],
  "vector_indexes": [
    {
      "name": "support-rag-index",
      "embedding_model": "text-embedding-...",
      "doc_count": 20031
    }
  ]
}
```

This gives teams traceability.

---

# 5. Overall scanner flow

```text
1. Load aisec.yml policy
2. Build repo inventory
3. Detect changed files from git diff
4. Classify files by layer
5. Run analyzers
6. Compare against baseline
7. Normalize findings
8. Apply allowlists/waivers
9. Score severity
10. Output CLI + JSON + SARIF
11. Fail or pass based on policy
```

Example command:

```bash
aisec scan . \
  --policy aisec.yml \
  --baseline .aisec/baseline.json \
  --format sarif \
  --output aisec.sarif
```

---

# 6. Policy file design

Create `aisec.yml`.

```yaml
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
  allowed_formats:
    - safetensors
    - onnx
    - gguf
  blocked_formats:
    - pkl
    - pickle
  require_sha256: true
  require_known_source: true
  require_revision_pin: true
  allow_trust_remote_code: false
  approved_model_sources:
    - huggingface.co/company-approved
    - s3://company-model-registry/

data_policy:
  require_manifest: true
  require_hashes: true
  require_owner: true
  allowed_sources:
    - s3://company-approved-data/
    - https://docs.company.com/
  max_duplicate_rate: 0.05
  max_new_source_ratio: 0.02
  max_label_jsd: 0.10
  scan_for_prompt_injection: true
  scan_for_secrets: false

rag_policy:
  require_source_metadata: true
  require_doc_owner: true
  block_instruction_like_content: true
  scan_hidden_html: true
  allowed_domains:
    - docs.company.com
    - help.company.com

code_policy:
  block_pickle_load: true
  block_unsafe_torch_load: true
  block_eval_exec: true
  block_trust_remote_code: true
  require_tool_allowlist: true

dependency_policy:
  run_pip_audit: true
  run_osv_scanner: true
  run_gitleaks: false
  require_lockfile: true
  block_critical_cves: true

output:
  sarif: true
  json: true
  markdown_summary: true
```

---

# 7. Finding format

Every analyzer should emit the same structure.

```json
{
  "rule_id": "ceres.rag.instruction.ignore_context",
  "severity": "high",
  "layer": "rag",
  "file": "docs/vendor_policy.md",
  "line": 42,
  "message": "RAG document contains instruction-like text that may manipulate the model.",
  "evidence": {
    "matched_text_preview": "ignore previous instructions",
    "source": "docs/vendor_policy.md"
  },
  "frameworks": {
    "owasp_llm": ["LLM01", "LLM04"],
    "mitre_atlas": ["poisoning"]
  },
  "recommendation": "Review the document source, remove instruction-like content, or mark the document as untrusted for retrieval."
}
```

NIST’s adversarial ML taxonomy organizes AI attacks by model type, lifecycle stage, attacker goals, capabilities, and knowledge, so mapping findings to lifecycle stages makes your output easier for security teams to understand. ([NIST Computer Security Resource Center][17])

---

# 8. Suggested repo structure

```text
aisec/
  pyproject.toml
  README.md

  aisec/
    cli.py
    config.py
    inventory/
      walker.py
      classifier.py
      git_diff.py

    analyzers/
      code/
        python_ast.py
        semgrep_adapter.py
        rules/
      model/
        scanner.py
        modelaudit_adapter.py
        modelscan_adapter.py
        safetensors_meta.py
        pickle_static.py
      data/
        manifest.py
        fingerprint.py
        drift.py
        duplicates.py
        rare_triggers.py
        cleanlab_adapter.py
      rag/
        text_extract.py
        injection_patterns.py
        hidden_html.py
      prompt/
        prompt_rules.py
      deps/
        pip_audit_adapter.py
        osv_adapter.py
        gitleaks_adapter.py
      bom/
        aibom.py

    rules/
      registry.py
      loader.py
      schema.py

    findings/
      model.py
      normalizer.py
      severity.py
      waivers.py

    reporters/
      cli.py
      json.py
      sarif.py
      markdown.py

    baseline/
      create.py
      compare.py
      store.py

  examples/
    vulnerable-ai-repo/
    clean-ai-repo/

  tests/
```

---

# 9. MVP feature set

## MVP 1: Static repo scanner

Goal: produce useful findings fast.

Features:

```text
aisec init
aisec scan .
aisec baseline create
aisec bom
JSON output
SARIF output
pre-commit support
GitHub Action support
```

Rules:

```text
CRITICAL ceres.model.artifact.pickle_format
CRITICAL ceres.model.loader.remote_code_enabled
HIGH ceres.model.loader.revision_unpinned
HIGH ceres.model.loader.torch_unsafe_load
HIGH ceres.rag.instruction.ignore_context
HIGH ceres.dataset.manifest_missing
HIGH ceres.dataset.hash_missing
MEDIUM ceres.dataset.duplicate_flood
MEDIUM ceres.dataset.label_distribution_drift
MEDIUM ceres.supplychain.dependency_unpinned
```

## MVP 2: Dataset/RAG poisoning layer

Goal: become more than a wrapper.

Features:

```text
dataset manifest validator
dataset hash checker
row-level fingerprinting
duplicate/near-duplicate detector
label drift detector
rare phrase repetition detector
source/domain allowlist
RAG prompt-injection linter
hidden HTML/Markdown scanner
baseline comparison
```

This is the part that can feel fresh.

## MVP 3: Model supply-chain layer

Features:

```text
model provenance
model hash verification
model source allowlist
revision pin check
tokenizer diff
chat template diff
LoRA adapter metadata diff
safe format recommendation
ModelScan/ModelAudit integration
```

## MVP 4: AI-BOM + framework mapping

Features:

```text
Ceres AI-BOM output
OWASP LLM mapping
OWASP ML mapping
MITRE ATLAS mapping
NIST lifecycle stage mapping
```

MITRE ATLAS is a knowledge base for threats to AI systems and includes AI-specific concepts like poisoning and manipulation, so mapping findings to ATLAS would make your scanner more useful to security teams. ([MITRE ATLAS][18])

---

# 10. The “early” features worth building

These are the parts where you can stand out.

## 1. RAG corpus security linting

Most teams scan code. Fewer scan their knowledge base as an attack surface.

Example:

```text
HIGH ceres.rag.instruction.indirect_injection
Document contains model-targeting instructions and was added from a new external source.
```

## 2. Dataset manifest diffing

Not just “data drift.” More like:

```text
This PR changed the training set.
The source changed.
The labels shifted.
The duplicate rate spiked.
The manifest was not updated.
```

## 3. Tokenizer and chat template diff

Backdoors can hide outside obvious weight changes.

Check:

```text
special_tokens_map.json
tokenizer.json
tokenizer_config.json
chat_template
added_tokens.json
```

Finding:

```text
HIGH ceres.model.tokenizer.special_token_drift
New special token "<|admin_override|>" added since baseline.
```

## 4. LoRA adapter policy

Many teams use adapters. Scan:

```text
adapter_config.json
target_modules
base_model_name_or_path
rank
alpha
weight file hash
```

Finding:

```text
HIGH ceres.model.lora.base_model_drift
Adapter claims base model A but project config loads base model B.
```

## 5. AI-BOM as a security artifact

Generate a machine-readable artifact that says:

```text
This AI app uses these models, datasets, prompts, tools, indexes, embeddings, and dependencies.
```

That is valuable for compliance and incident response.

## 6. Git diff-aware scanning

For pre-commit, don’t scan everything every time.

```bash
aisec scan --changed-only
```

But for CI:

```bash
aisec scan --full
```

## 7. Waiver workflow

Security tools need waivers or developers will hate them.

```yaml
waivers:
  - rule_id: ceres.model.loader.remote_code_enabled
    file: src/research_loader.py
    reason: "Research-only script, not shipped"
    expires: "2026-08-01"
    approved_by: "security-team"
```

Expired waivers should fail.

---

# 11. Example CLI behavior

```bash
$ aisec scan .

AI Security Scan

CRITICAL  ceres.model.artifact.pickle_format
          models/final.pkl
          Pickle-based model artifact may execute code during deserialization.

HIGH      ceres.model.loader.remote_code_enabled
          src/load_model.py:17
          Model loader uses trust_remote_code=True.

HIGH      ceres.rag.instruction.ignore_context
          docs/vendor_policy.md:44
          RAG document contains instruction-like text.

MEDIUM    ceres.dataset.label_distribution_drift
          data/train.parquet
          Label distribution changed beyond policy threshold.

MEDIUM    ceres.dataset.duplicate_flood
          data/train.parquet
          Duplicate rate increased from 1.8% to 9.4%.

Scan result: FAILED
Policy: high and critical findings fail CI.
```

---

# 12. GitHub Actions integration

```yaml
name: AI Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  aisec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install aisec
        run: pip install aisec-scanner

      - name: Run scan
        run: |
          aisec scan . \
            --policy aisec.yml \
            --baseline .aisec/baseline.json \
            --format sarif \
            --output aisec.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aisec.sarif
```

---

# 13. Pre-commit integration

The pre-commit framework manages hooks and runs them before commits. ([pre-commit.com][19])

```yaml
repos:
  - repo: local
    hooks:
      - id: aisec
        name: AI Security Scanner
        entry: aisec scan . --changed-only --policy aisec.yml
        language: system
        pass_filenames: false
```

Fast mode should only run:

```text
code rules
prompt rules
RAG text rules
small model metadata checks
manifest/hash checks
```

Full mode can run heavier dataset drift/duplicate checks.

---

# 14. Rule taxonomy

Use a Ceres-owned rule ID system. Do not copy upstream rule IDs from Semgrep,
ModelScan, Gitleaks, or any other scanner.

```text
ceres.model.*
ceres.dataset.*
ceres.rag.*
ceres.agent.*
ceres.tool.*
ceres.mcp.*
ceres.aibom.*
ceres.supplychain.*
ceres.policy.*
ceres.engine.*
```

Example full list:

```text
ceres.model.loader.remote_code_enabled
ceres.model.loader.torch_unsafe_load
ceres.model.loader.pickle_deserialize
ceres.ai_code.dynamic_execution
ceres.agent.tool.unreviewed_capability
ceres.rag.retrieval.filter_missing

ceres.model.artifact.pickle_format
ceres.model.artifact.format_not_allowed
ceres.model.artifact.source_missing_or_unapproved
ceres.model.config.revision_unpinned
ceres.model.artifact.hash_missing
ceres.model.tokenizer.drift
ceres.model.chat_template.drift
ceres.model.lora.base_model_drift

ceres.dataset.manifest_missing
ceres.dataset.hash_missing
ceres.dataset.source_unapproved
ceres.dataset.source_new_domain
ceres.dataset.schema_changed
ceres.dataset.size_spike
ceres.dataset.duplicate_flood
ceres.dataset.label_distribution_drift
ceres.dataset.rare_phrase_repetition
ceres.dataset.outlier_cluster
ceres.dataset.synthetic_spam

ceres.rag.instruction.ignore_context
ceres.rag.instruction.system_override
ceres.rag.instruction.secret_request
ceres.rag.hidden_instruction_markup
ceres.rag.source_unknown
ceres.rag.duplicate_flood

ceres.prompt.system_context_leakage_risk
ceres.prompt.output_schema_missing
ceres.prompt.system_context_user_slot
optional: ceres.prompt.secret_literal

ceres.agent.tool.allowlist_missing
ceres.agent.tool.shell_without_allowlist
ceres.agent.tool.file_write_unrestricted
ceres.agent.tool.browser_unrestricted
ceres.agent.action.confirmation_missing

ceres.supplychain.vulnerable_dependency
ceres.supplychain.dependency_unpinned
ceres.supplychain.lockfile_missing
ceres.supplychain.remote_script_pipe
ceres.supplychain.git_dependency_unpinned

ceres.aibom.coverage_missing
ceres.aibom.model_missing
ceres.aibom.dataset_missing
ceres.aibom.prompt_missing
```

---

# 15. Severity model

Use deterministic severity first.

```text
CRITICAL
- unsafe model deserialization artifact committed
- unrestricted shell tool in production agent
- trust_remote_code=True with untrusted source
- dataset changed with no manifest/hash
- secret found in prompt/config

HIGH
- model source unknown
- model not revision-pinned
- RAG prompt injection found
- new unapproved dataset source
- tokenizer/chat template changed unexpectedly

MEDIUM
- duplicate spike
- label drift
- dataset size anomaly
- missing owner metadata
- dependency unpinned

LOW
- missing license
- missing model card
- missing dataset description
```

Later, add score-based severity:

```text
severity = impact × confidence × exploitability × policy sensitivity
```

---

# 16. Baseline design

Create `.aisec/baseline.json`.

```json
{
  "version": 1,
  "created_at": "2026-05-12T00:00:00Z",
  "models": {
    "models/adapter.safetensors": {
      "sha256": "...",
      "format": "safetensors",
      "tensor_count": 291,
      "tokenizer_sha256": "..."
    }
  },
  "datasets": {
    "data/train.parquet": {
      "sha256": "...",
      "row_count": 98231,
      "duplicate_rate": 0.018,
      "label_distribution": {
        "refund": 0.31,
        "billing": 0.24,
        "technical": 0.40,
        "abuse": 0.05
      },
      "top_sources": ["docs.company.com"]
    }
  },
  "rag": {
    "docs/": {
      "doc_count": 2031,
      "top_domains": ["docs.company.com"],
      "index_hash": "..."
    }
  }
}
```

Then the scanner compares PR state to baseline.

---

# 17. Technical stack

For MVP, use Python.

Reasons:

```text
ML/data ecosystem is Python-first
easy AST parsing
easy Pandas/Polars/DuckDB support
easy integration with model scanners
easy CLI packaging
```

Suggested libraries:

```text
CLI: Typer or Click
Terminal UI: Rich
Config: Pydantic + PyYAML
Data: Polars, Pandas, DuckDB, PyArrow
Text similarity: rapidfuzz, datasketch, scikit-learn
Model metadata: safetensors, onnx, h5py where safe
SARIF: custom JSON writer or sarif-tools style model
Code parsing: ast, libcst, semgrep adapter
Secrets: gitleaks adapter
Deps: pip-audit, osv-scanner adapters
```

Later, move the file classifier or scanner core to Go/Rust if speed matters.

---

# 18. What the first prototype should do

Build this exact first version:

```bash
aisec init
aisec scan .
aisec baseline create
```

With these scanners:

```text
1. File inventory
2. Python AST rules
3. Prompt/RAG text rules
4. Model file extension/hash/source checks
5. Dataset manifest/hash checks
6. Basic duplicate and label drift checks
7. Gitleaks wrapper
8. pip-audit wrapper
9. JSON + SARIF output
```

Do not start with fancy ML detection. Start with rules that are obvious and valuable.

---

# 19. Example first rules to implement

```text
1. Block .pkl / .pickle model files
2. Warn on .pt / .bin unless hash and source exist
3. Prefer .safetensors
4. Detect trust_remote_code=True
5. Detect pickle.load
6. Detect torch.load without safe policy
7. Detect eval/exec
8. Detect missing dataset manifest
9. Detect dataset file changed but hash not updated
10. Detect RAG prompt-injection phrases
11. Detect hidden HTML in RAG docs
12. Detect unpinned Hugging Face model
13. Detect prompt/config secrets
14. Detect unrestricted agent tools
15. Detect missing AI-BOM
```

That alone is enough for a useful demo.

---

# 20. How to position it

Don’t say:

```text
We detect all AI vulnerabilities.
```

Say:

```text
We are building AI-SAST for repos.
```

Or:

```text
Pre-CI security scanning for models, datasets, RAG docs, prompts, and AI supply chain.
```

Or:

```text
Semgrep + Gitleaks + ModelScan-style workflow, but purpose-built for AI repos.
```

---

# 21. Open-source vs paid strategy

## Open-source CLI

Give away:

```text
local CLI
core rules
model artifact checks
RAG injection linter
dataset manifest checks
SARIF output
GitHub Action
```

## Paid / advanced later

Charge for:

```text
team dashboard
policy management
enterprise rule packs
private model registry integration
Hugging Face/org scanning
dataset lineage connectors
vector DB connectors
waiver approval workflows
compliance reports
continuous monitoring
```

This mirrors the usual developer-security playbook.

---

# 22. Biggest risks

## Risk 1: False positives

Security scanners get ignored if noisy.

Solution:

```text
confidence score
waivers
baseline mode
changed-only scan
clear evidence
clear fix recommendation
```

## Risk 2: “Static analyzer” overclaiming poisoning detection

Do not claim certainty.

Say:

```text
poisoning indicators
provenance violations
baseline anomalies
suspicious data changes
```

## Risk 3: Existing tools expand into your space

This is why your wedge must be:

```text
repo-native AI-SAST + dataset/RAG poisoning policy
```

Not just model scanning.

## Risk 4: Scanning untrusted model files is itself risky

Design principle:

```text
never import
never deserialize unsafely
never execute
parse in sandbox
limit file size
limit recursion
block archive traversal
```

---

# 23. Best final architecture summary

The product should be:

```text
aisec
├── AI-SAST code scanner
├── model artifact scanner
├── dataset poisoning-risk scanner
├── RAG corpus injection scanner
├── prompt/config scanner
├── dependency scanner wrappers
├── AI-BOM generator
├── baseline/diff engine
├── policy engine
├── waiver system
└── SARIF/JSON/CLI reporters
```

The design-reference mapping:

```text
Semgrep        -> YAML rules + developer workflow
Gitleaks       -> fast local secret scanning model
ModelScan      -> safe model artifact scanning idea
ModelAudit     -> broad model format scanning direction
Picklescan     -> pickle opcode/static suspicious action detection
Fickling       -> pickle decompile/allowlist approach
garak          -> probes/detectors for later dynamic mode
promptfoo      -> CI-friendly LLM eval/red-team workflow
PyRIT          -> extensible red-team architecture inspiration
Cleanlab       -> dataset issue/outlier/label error signals
Evidently/TFDV -> drift/schema/anomaly detection concepts
Ceres AI-BOM  -> AI/ML inventory output direction
```

The strongest first product:

```text
AI-SAST pre-CI scanner for:
- unsafe model loading
- untrusted model artifacts
- RAG prompt injection
- dataset poisoning indicators
- missing dataset/model provenance
- risky agent/tool configs
- AI-BOM gaps
```

This is very buildable, and the “dataset/RAG poisoning before CI” angle is the part I’d push hardest.

---

# 24. Current implementation checkpoint

Date: 2026-05-13.

The repository now has a working Python MVP named `ceres`, not `aisec`. The
product shape still matches the original plan: developer-first AI-SAST for
repos, with CLI scanning across code, prompts, configs, models, datasets, RAG
docs, dependencies, baselines, AI-BOM, waivers, and reports.

## What exists now

### CLI and workflow

Implemented:

```text
ceres init
ceres scan .
ceres scan . --json-out report.json --sarif-out report.sarif
ceres baseline .
ceres bom .
ceres list-rules
```

The CLI resolves `ceres.yml`, `.ceres/baseline.json`, and `ai-bom.json`
relative to the scanned repo. This matters for CI and pre-commit because a user
can run:

```bash
ceres scan path/to/repo
```

without accidentally reading policy files from the caller's current directory.

### Inventory

Implemented:

```text
Python files
notebooks as code inventory entries
prompt files
YAML/JSON/TOML configs
model artifacts and tokenizer/config metadata files
datasets
dataset manifests
RAG docs
dependency manifests
CI/Docker files
```

The inventory is simple but useful. It classifies files by extension, known file
names, and directory hints.

### Code analyzer

Implemented Python AST rules:

```text
ceres.model.loader.remote_code_enabled
ceres.model.loader.revision_unpinned
ceres.model.loader.torch_unsafe_load
ceres.model.loader.pickle_deserialize
ceres.model.loader.joblib_deserialize
ceres.ai_code.dynamic_execution
ceres.agent.tool.shell_without_allowlist
optional: ceres.prompt.secret_literal
```

Python is a natural first implementation language here because the standard
library exposes Python AST parsing directly. The official `ast` module is
designed for applications that need to process Python abstract syntax trees and
can generate ASTs through `ast.parse()` or `compile(..., PyCF_ONLY_AST)`. [20]

### Prompt and config scanner

Implemented:

```text
ceres.prompt.system_context_user_slot
ceres.agent.tool.shell_without_allowlist
ceres.model.config.revision_unpinned
ceres.model.artifact.source_missing_or_unapproved for unapproved configured model sources
optional: ceres.prompt.secret_literal
```

It scans plain prompt files plus YAML/JSON configs.

### Model artifact scanner

Implemented:

```text
ceres.model.artifact.pickle_format
ceres.model.artifact.format_not_allowed
ceres.model.artifact.prefer_safetensors
ceres.model.artifact.pickle_opcode_risk
ceres.model.artifact.source_missing_or_unapproved
ceres.model.artifact.hash_drift
ceres.model.tokenizer.special_token_drift
ceres.model.chat_template.drift
ceres.model.lora.base_model_drift
```

The scanner still follows the critical design rule: do not import or execute
model artifacts. Pickle-like files are inspected with `pickletools`, not loaded.

The current implementation now parses safetensors headers and tensor metadata
without importing the model, records per-tensor hashes and compact numeric
stats, and compares them against baseline state. This keeps the scanner aligned
with safetensors' safe-layout model while adding Ceres-owned integrity and
poisoning-indicator checks. [21]

### Dataset scanner

Implemented:

```text
ceres.dataset.manifest_missing
ceres.dataset.manifest_incomplete
ceres.dataset.hash_missing
ceres.dataset.hash_drift
ceres.dataset.source_unapproved
ceres.dataset.duplicate_flood
ceres.dataset.label_distribution_drift
ceres.dataset.rare_phrase_repetition
ceres.dataset.manifest_stale_hash
```

It handles CSV/TSV/JSONL/NDJSON and Parquet when `pyarrow` is installed. It can
compare against `.ceres/baseline.json`.

### RAG corpus scanner

Implemented:

```text
ceres.rag.instruction.ignore_context
ceres.rag.instruction.system_override
ceres.rag.instruction.secret_request
ceres.rag.instruction.tool_request
ceres.rag.instruction.exfiltration
ceres.rag.hidden_instruction_markup
ceres.rag.encoded_payload
ceres.rag.invisible_control_chars
ceres.rag.source_metadata_missing
ceres.rag.owner_missing
ceres.rag.domain_unapproved
```

The RAG rules are intentionally phrase/pattern based. They are useful for early
CI gates but should be treated as high-signal linting, not full semantic
analysis.

### Dependency and supply-chain scanner

Implemented static checks:

```text
ceres.supplychain.dependency_unpinned
ceres.supplychain.lockfile_missing
ceres.supplychain.git_dependency_unpinned
ceres.supplychain.remote_script_pipe
ceres.supplychain.docker_image_unpinned
ceres.supplychain.scanner_unavailable
ceres.supplychain.vulnerable_dependency via pip-audit when installed
ceres.supplychain.secret_scanner_hit.* only if gitleaks is explicitly enabled
```

The scanner now makes missing optional scanners visible. If policy enables
`pip-audit`, `gitleaks`, or `osv-scanner` but they are not installed, Ceres emits
`ceres.supplychain.scanner_unavailable` instead of silently pretending that coverage exists.

### AI-BOM

Implemented:

```text
Ceres-owned JSON envelope
model components
dataset components
prompt components
ceres.aibom.coverage_missing / missing component checks
```

This is directionally right, but the default format should remain Ceres-owned
so the implementation and naming are clearly original.

### Baseline and waivers

Implemented:

```text
model SHA-256 baseline
dataset row count / duplicate rate / label distribution / top ngrams baseline
RAG doc list baseline
active waivers
expired waiver findings
severity gates
fail-closed analyzer errors
```

Analyzer errors are now high-severity findings because an incomplete security
scan should fail closed.

### Reporters

Implemented:

```text
CLI table
JSON report
SARIF 2.1.0 report
```

SARIF output makes the scanner viable for GitHub code scanning.

### Test/demo state

Implemented:

```text
examples/vulnerable-ai-repo
examples/clean-ai-repo
tmp/synthetic-ai-repo local demo
10 pytest tests
```

The synthetic repo demonstrates the intended use case: unsafe model loading,
pickle artifacts, prompt secrets, RAG injection, stale dataset hashes, unknown
dataset source, unpinned dependencies, and unsafe Docker install scripts.

---

# 25. What is still lacking

## Product gaps

The product is useful as an MVP, but it is still more of a curated scanner than
a full platform.

Missing:

```text
changed-only scanning
git diff aware baselines
markdown summary reporter
pre-commit sample file in repo
GitHub Action file in repo
configurable rule packs
custom user-authored YAML rules
rule documentation pages
rule tests per analyzer
machine-readable rule registry
```

The biggest product gap is the absence of a Semgrep-like rule system. Rules are
currently hardcoded in Python. That was pragmatic for the MVP, but users will
eventually need to add internal rules without editing Ceres source code.

## Code analyzer gaps

Missing:

```text
JavaScript/TypeScript scanner
notebook cell AST scanning
LangChain-specific patterns
LlamaIndex-specific patterns
OpenAI SDK misuse rules
tool allowlist validation beyond obvious shell-like tools
RAG no source filter / no citation requirement rules
taint flow from user input into system prompt or tool args
```

The current AST checks are syntactic. They do not yet model data flow.

## Model scanner gaps

Missing:

```text
safetensors header parsing
per-tensor SHA-256 baseline
layer shape diff
dtype diff
NaN/Inf detection where safely inspectable
tensor norm / sparsity anomaly indicators
ONNX metadata parsing
H5/Keras metadata parsing without unsafe execution
GGUF metadata parsing
archive traversal checks for model archives
signed artifact verification
model card and license checks
ModelScan / ModelAudit integration
```

Important: layer scanning should be framed as poisoning **indicator** detection,
not proof of poisoning. Static tensor inspection can flag strange layer names,
shape changes, extreme values, or large norm drift, but a backdoor may only be
observable through trigger-based dynamic evaluation.

## Dataset scanner gaps

Missing:

```text
schema type validation
new/missing column checks
null spike checks
dataset size jump checks
source/domain distribution tracking
new source ratio
near-duplicate detection
rare trigger checks over new rows only
label flip checks against stable IDs
contradictory examples
synthetic-looking row heuristics
embedding/outlier cluster analysis
HTML/Markdown prompt-injection checks inside dataset text fields
dataset owner/source enforcement for every file entry
```

Current dataset checks are intentionally simple and explainable.

## RAG scanner gaps

Missing:

```text
PDF text extraction
HTML text extraction with proper parser
Notion/Confluence export support
vector DB source dump support
duplicate spam detection
source/domain baseline diff
index changed without rebuild check
hidden Unicode normalization report
external link allowlist with path-level policy
semantic prompt-injection classifier
```

## Dependency scanner gaps

Missing:

```text
OSV-Scanner adapter
Semgrep adapter
OpenSSF Scorecard adapter
Dockerfile parser instead of regex
GitHub Actions parser instead of regex
curl | bash checksum/signature verification
unknown Python package index checks
unpinned direct URL package checks
lockfile consistency checks
```

## AI-BOM gaps

Missing:

```text
dependencies
tools
agent tool list
vector indexes
embedding models
dataset provenance fields
model source/revision/license/model card fields
prompt role metadata
relationships between app components
validation against the Ceres AI-BOM schema
```

The current AI-BOM is useful but thin.

## Engineering gaps

Missing:

```text
structured rule registry
deduplication of related findings
parallel file scanning
streaming large file reads
central evidence redaction
performance benchmarks
golden SARIF/JSON snapshots
fuzz tests for parsers
safe archive parsing limits
Windows path tests
packaging/release workflow
```

---

# 26. What to implement next

## P0: Make the current MVP production-shaped

1. Add a rule registry:

```text
ceres/rules/registry.py
ceres/rules/schema.py
ceres/rules/builtin/*.yaml
```

Keep Python analyzers for complex logic, but expose metadata, severity,
recommendations, and framework mappings through structured rule definitions.

2. Add changed-only scanning:

```bash
ceres scan . --changed-only
ceres scan . --base-ref origin/main
```

This is important for pre-commit speed.

3. Add markdown reporter:

```bash
ceres scan . --markdown-out ceres-summary.md
```

This helps PR comments and human review.

4. Add repo-native CI/pre-commit templates:

```text
.github/workflows/ceres.yml
.pre-commit-config.yaml example
```

## P1: Implement model layer/tensor indicators

Start with safetensors because it is the safest and cleanest format to inspect.

Features:

```text
ceres.model.tensor.shape_changed
ceres.model.tensor.dtype_changed
ceres.model.tensor.hash_drift
ceres.model.tensor.nan_or_inf
ceres.model.tensor.norm_drift
ceres.model.tensor.sparsity_drift
ceres.model.tensor.range_anomaly
ceres.model.tensor.added
ceres.model.tensor.removed
ceres.model.tensor.suspicious_name
```

Baseline format:

```json
{
  "models/adapter.safetensors": {
    "sha256": "...",
    "tensors": {
      "lm_head.weight": {
        "sha256": "...",
        "shape": [32000, 4096],
        "dtype": "F16",
        "norm": 123.4,
        "nan_count": 0,
        "inf_count": 0
      }
    }
  }
}
```

Severity guidance:

```text
HIGH   shape/dtype changed unexpectedly
HIGH   NaN/Inf appears in model weights
MEDIUM tensor norm drift exceeds threshold
MEDIUM layer added/removed compared with baseline
LOW    layer name matches suspicious keywords but no other signal
```

Do not write findings that say "this layer is poisoned." Write findings that say
"this layer has poisoning-risk indicators."

## P2: Improve dataset/RAG poisoning layer

Implement:

```text
schema checks
source/domain distribution baseline
new source ratio
near-duplicate flood detection
rare trigger repetition over changed rows
prompt-injection scan inside dataset text columns
RAG duplicate spam checks
PDF/HTML extraction
```

## P3: Integrations

Implement:

```text
osv-scanner adapter
semgrep adapter
modelscan/modelaudit adapter
OpenSSF Scorecard adapter
GitHub Action upload docs
```

Keep wrappers optional. If enabled by policy and missing, keep emitting
`ceres.supplychain.scanner_unavailable`.

---

# 27. Python vs Rust decision

## Why the MVP is in Python

Python was the right first implementation language because this product is
scanning AI/ML repositories, and the ecosystem is Python-first.

Concrete reasons:

```text
Python has built-in AST parsing for Python code.
Most AI projects use Python config/code conventions.
Dataset and model metadata libraries are easiest to reach from Python.
Typer/Rich/Pydantic/PyYAML make CLI/config/reporting fast to build.
pip-audit, gitleaks wrappers, pyarrow, safetensors, and ML tooling are easy to call.
The early product risk is rule quality, not raw CPU speed.
```

The first job was to validate scanner coverage and finding quality. Python let
us do that quickly.

## Would Rust make a difference?

Yes, Rust can make a real difference, but mostly in the scanner core once the
rules and product workflow are proven.

Rust's official positioning is relevant: it is fast, memory-efficient, has no
garbage collector, integrates with other languages, and provides ownership-based
memory and thread safety. [23] [24]

Rust would help most for:

```text
parallel repo walking
large file hashing
safe archive parsing
SARIF/JSON generation at scale
high-volume regex/text scanning
safetensors/ONNX/GGUF metadata parsing
tensor statistics and baseline diffs
single static binary distribution
lower memory usage in huge monorepos
```

Rust would help least for:

```text
rapidly adding AI-specific rules
calling Python-first ML/data libraries
experimentation with dataset heuristics
integrating Python package scanners
shipping early policy/CLI changes
```

Ruff is the strongest precedent for a Rust scanner in the Python ecosystem: it
is a Python linter/formatter written in Rust and documents large performance
wins compared with traditional Python tooling. [25]

## Recommended architecture

Do not rewrite the whole product in Rust yet.

Use this path:

```text
Phase 1: Python product shell
  CLI, policy, findings, reporters, rule orchestration, integrations.

Phase 2: Rust accelerator modules
  File walking, hashing, archive inspection, safetensors/ONNX/GGUF metadata,
  tensor statistics, fast text scanning.

Phase 3: Optional Rust standalone scanner
  Only if distribution/performance becomes a bottleneck.
```

This hybrid route is practical because PyO3 supports writing native Python
modules in Rust or embedding Python from Rust. [26] `maturin` is the usual
packaging path for building Rust-backed Python wheels. [27]

## Decision

Stay in Python for the next product milestone.

Add Rust only when one of these becomes true:

```text
scans over medium repos take more than 5-10 seconds
model/tensor baseline analysis becomes CPU-bound
archive/model parsing needs stronger memory-safety guarantees
users ask for a single binary with no Python environment
CI cost becomes sensitive to scan time
```

The likely final shape is:

```text
Python CLI + policy engine + integrations
Rust scanner core for performance-sensitive parsing/hashing/tensor work
```

That gives us Python's AI ecosystem and Rust's speed/safety where it actually
matters.

---

# 28. Priority checklist and tool-pattern map

Important scope correction:

```text
Ceres is not a generic secret/leak scanner.
Skylos owns generic secrets, repo leak detection, credential exposure, and
general-purpose secret scanning.
Ceres owns AI model/artifact integrity and AI-specific poisoning-risk signals.
```

Rule/IP policy:

```text
Ceres uses Ceres-owned rule IDs.
Ceres rules must be original implementations.
Do not copy upstream scanner rule IDs.
Do not copy upstream scanner rule bodies.
Use upstream tools only as inspiration, optional integrations, or public-format
references.
```

Any generic secret scanning in the current MVP should be treated as demo-only or
integration-only. The product should not compete with Skylos. If a user wants
secret scanning, Ceres should hand off to Skylos or include a Skylos integration
later.

Use this as the working build checklist. Status values:

```text
[x] implemented
[~] partially implemented
[ ] not done
```

## P0: Core MVP, must stay solid

```text
[x] Repo inventory
    What it does: classifies code, prompts, configs, models, datasets, RAG docs,
    dependency files, CI files.
    Inspired by: Gitleaks / Semgrep style fast repo traversal and file
    targeting.

[x] CLI workflow
    What it does: ceres init / scan / baseline / bom / list-rules.
    Inspired by: Gitleaks, pip-audit, OSV-Scanner, Semgrep CLI-first workflow.

[x] Finding format
    What it does: normalizes rule_id, severity, layer, file, evidence,
    frameworks, recommendation.
    Inspired by: Semgrep findings + SARIF conventions.

[x] Severity gate
    What it does: fails CI on configured severities.
    Inspired by: Semgrep/Gitleaks CI gate behavior.

[x] Waivers
    What it does: suppresses approved findings and surfaces expired waivers.
    Inspired by: enterprise SAST waiver/suppression workflows.

[x] CLI reporter
    What it does: human-readable scan table.
    Inspired by: developer-first scanners like Gitleaks and pip-audit.

[x] JSON reporter
    What it does: machine-readable report.
    Inspired by: Semgrep, pip-audit, Gitleaks normalized outputs.

[x] SARIF reporter
    What it does: GitHub code scanning compatible output.
    Inspired by: GitHub code scanning / SARIF upload workflow.

[x] Fail-closed analyzer errors
    What it does: analyzer crashes become high-severity findings.
    Inspired by: security scanner principle that incomplete scans should not
    silently pass.
```

## P0: AI-SAST rules

```text
[x] Detect trust_remote_code=True
    Rule: ceres.model.loader.remote_code_enabled
    Inspired by: Semgrep-style code rules, AI supply-chain risk patterns.

[x] Detect unpinned Hugging Face from_pretrained calls
    Rule: ceres.model.loader.revision_unpinned
    Inspired by: dependency pinning practice in pip-audit/OSV/Gitleaks-style
    supply-chain scanners.

[x] Detect unsafe torch.load
    Rule: ceres.model.loader.torch_unsafe_load
    Inspired by: ModelScan / Picklescan / Fickling safety model: do not trust
    pickle-backed deserialization.

[x] Detect pickle.load / joblib.load
    Rules: ceres.model.loader.pickle_deserialize, ceres.model.loader.joblib_deserialize
    Inspired by: Picklescan and Fickling suspicious deserialization focus.

[x] Detect eval/exec
    Rule: ceres.ai_code.dynamic_execution
    Inspired by: classic SAST patterns, Semgrep-style rules.

[~] Detect hard-coded secrets in prompts/configs
    Rule: ceres.prompt.secret_literal
    Status: implemented but should be deprecated or moved behind an optional
    Skylos handoff.
    Decision: not core Ceres. Keep only when the secret is inside an AI prompt,
    model config, tokenizer config, or agent config and creates AI-specific risk.
    Generic leaks belong to Skylos.

[x] Detect unrestricted shell tools
    Rule: ceres.agent.tool.shell_without_allowlist
    Inspired by: OWASP LLM tool/agency risk patterns and Semgrep config rules.

[ ] Add JavaScript/TypeScript AI rules
    Target rules: JS model SDK misuse, tool calls, prompt injection in templates.
    Reference: Semgrep multi-language rule architecture.

[ ] Add data-flow/taint tracking
    Target rules: user input flows into system prompt, tool args, shell command,
    retrieval filters.
    Reference: Semgrep taint/data-flow model.
```

## P0: Model artifact safety

```text
[x] Block pickle model artifacts
    Rule: ceres.model.artifact.pickle_format
    Inspired by: ModelScan / ModelAudit / Picklescan.

[x] Static pickle opcode scan
    Rule: ceres.model.artifact.pickle_opcode_risk
    Inspired by: Picklescan and Fickling.

[x] Prefer safetensors over PyTorch pickle-backed formats
    Rule: ceres.model.artifact.prefer_safetensors
    Inspired by: safetensors safety model and ModelScan safe scanning design.

[x] Flag unsafe/unapproved model formats
    Rule: ceres.model.artifact.format_not_allowed
    Inspired by: ModelScan / ModelAudit format policy.

[x] Model hash baseline comparison
    Rule: ceres.model.artifact.hash_drift
    Inspired by: supply-chain integrity checks / SBOM-BOM workflows.

[x] Missing model provenance/source metadata
    Rule: ceres.model.artifact.source_missing_or_unapproved
    Inspired by: CycloneDX ML-BOM provenance idea.

[~] Tokenizer/chat-template/LoRA metadata diff
    Rules: ceres.model.tokenizer.special_token_drift,
    ceres.model.chat_template.drift, ceres.model.lora.base_model_drift
    Inspired by: AI-specific supply-chain/backdoor surface analysis.

[x] Safetensors header parsing
    Target rules: tensor list, shape, dtype, metadata, per-tensor hash.
    Reference: safetensors safe tensor inspection.

[x] Model layer/tensor anomaly scan
    Implemented: ceres.model.tensor.added, ceres.model.tensor.removed,
    ceres.model.tensor.shape_changed, ceres.model.tensor.dtype_changed,
    ceres.model.tensor.hash_drift, ceres.model.tensor.suspicious_name,
    ceres.model.tensor.nan_or_inf, ceres.model.tensor.norm_drift,
    ceres.model.tensor.sparsity_drift, ceres.model.tensor.range_anomaly,
    ceres.model.safetensors.header_invalid, ceres.model.safetensors.header_oversized.
    Not done: cross-layer outlier scoring and non-safetensors tensor stats.
    Reference: ModelScan safe artifact scanning + safetensors metadata parsing
    + Evidently/TFDV-style anomaly thinking.

[ ] ONNX/H5/Keras/GGUF metadata scanners
    Target rules: unsafe format metadata, suspicious graph/operator metadata,
    source/license/model-card gaps.
    Reference: ModelAudit broad model format coverage.

[ ] Signed/provenanced artifact verification
    Target rules: ceres.model.signature_missing, ceres.model.signature_invalid.
    Reference: software supply-chain signing/SBOM workflows.
```

## P0: RAG corpus scanner

```text
[x] Prompt-injection phrase detection
    Rules: ceres.rag.instruction.ignore_context,
    ceres.rag.instruction.system_override,
    ceres.rag.instruction.secret_request,
    ceres.rag.instruction.tool_request,
    ceres.rag.instruction.exfiltration
    Inspired by: garak/promptfoo probe ideas, implemented as static lint.

[x] Hidden HTML/comment detection
    Rule: ceres.rag.hidden_instruction_markup
    Inspired by: indirect prompt-injection research patterns.

[x] Base64-looking blob detection
    Rule: ceres.rag.encoded_payload
    Inspired by: payload-smuggling and secret-scanner heuristics.

[x] Invisible Unicode detection
    Rule: ceres.rag.invisible_control_chars
    Inspired by: text normalization/security linting patterns.

[x] RAG metadata/domain policy
    Rules: ceres.rag.source_metadata_missing, ceres.rag.owner_missing,
    ceres.rag.domain_unapproved
    Inspired by: dataset provenance and CycloneDX-style source tracking.

[ ] PDF extraction
    Reference: document ingestion/RAG pipeline tooling.

[ ] Proper HTML parser
    Reference: robust static analyzers: parse structure, do not regex complex
    formats forever.

[ ] RAG duplicate spam / source drift
    Reference: dataset drift tools like Evidently/TFDV/whylogs.

[ ] Semantic indirect-prompt-injection classifier
    Reference: garak/promptfoo detector architecture, but keep optional.
```

## P0: Dataset poisoning-risk scanner

```text
[x] Dataset manifest required
    Rule: ceres.dataset.manifest_missing
    Inspired by: data provenance / TFDV schema-manifest mindset.

[x] Manifest completeness
    Rule: ceres.dataset.manifest_incomplete
    Inspired by: policy-as-code config validation.

[x] Dataset hash checks
    Rules: ceres.dataset.hash_missing, ceres.dataset.hash_drift, ceres.dataset.manifest_stale_hash
    Inspired by: supply-chain integrity and BOM workflows.

[x] Dataset source allowlist
    Rule: ceres.dataset.source_unapproved
    Inspired by: supply-chain allowlist policy.

[x] Duplicate spike
    Rule: ceres.dataset.duplicate_flood
    Inspired by: Cleanlab / TFDV / whylogs data-quality signals, reframed as
    poisoning indicators.

[x] Label drift
    Rule: ceres.dataset.label_distribution_drift
    Inspired by: Evidently / TFDV drift detection.

[x] Rare trigger repetition
    Rule: ceres.dataset.rare_phrase_repetition
    Inspired by: poisoning/backdoor trigger heuristics.

[ ] Schema type checks
    Reference: TensorFlow Data Validation.

[ ] Null spike / length spike / new column checks
    Reference: TFDV / Evidently anomaly detection.

[ ] New source ratio and source domination
    Reference: provenance-aware data drift.

[ ] Near-duplicate flood detection
    Reference: Cleanlab/outlier and dedup workflows.

[ ] Label flip detection
    Reference: data quality / weak supervision audit workflows.

[ ] Prompt-injection scan inside dataset text columns
    Reference: RAG prompt-injection linting.
```

## P1: Dependency and supply-chain scanner

```text
[x] Static unpinned dependency checks
    Rules: ceres.supplychain.dependency_unpinned, ceres.supplychain.git_dependency_unpinned
    Inspired by: pip-audit / OSV-Scanner dependency workflow.

[x] Missing lockfile policy
    Rule: ceres.supplychain.lockfile_missing
    Inspired by: reproducible build policy.

[x] Remote script pipe detection
    Rule: ceres.supplychain.remote_script_pipe
    Inspired by: SAST supply-chain rules.

[x] Docker image digest check
    Rule: ceres.supplychain.docker_image_unpinned
    Inspired by: container supply-chain scanners.

[~] pip-audit adapter
    Rule: ceres.supplychain.vulnerable_dependency
    Status: implemented but not central.
    Decision: keep optional only for AI dependency context; do not position as a
    core Ceres feature.

[~] gitleaks adapter
    Rule: ceres.supplychain.secret_scanner_hit.*
    Status: optional and off by default.
    Decision: generic leak scanning belongs to Skylos; keep this only as an
    explicit integration path, not as a Ceres differentiator.

[x] Missing external scanner visibility
    Rule: ceres.supplychain.scanner_unavailable
    Inspired by: fail-visible CI coverage principles.

[ ] OSV-Scanner adapter
    Reference: OSV-Scanner directly.

[ ] Semgrep adapter
    Reference: Semgrep directly.

[ ] OpenSSF Scorecard adapter
    Reference: OpenSSF Scorecard directly.

[ ] Real Dockerfile/GitHub Actions parsers
    Reference: static analysis parser-first design.
```

## P1: AI-BOM

```text
[x] Generate Ceres AI-BOM
    Includes: models, datasets, prompts.
    Inspired by: AI inventory and incident-response workflows.

[x] Warn when AI-BOM is missing/stale
    Rule: ceres.aibom.coverage_missing
    Inspired by: inventory completeness gates.

[ ] Add dependencies to AI-BOM
    Reference: dependency inventory completeness.

[ ] Add tools/agent permissions to AI-BOM
    Reference: AI-specific inventory and incident-response needs.

[ ] Add vector indexes and embedding models
    Reference: AI runtime inventory plus RAG operational inventory.

[ ] Add model source/revision/license/model-card fields
    Reference: AI inventory and Hugging Face model-card conventions.

[ ] Validate generated BOM against Ceres AI-BOM schema
    Reference: Ceres-owned schema tooling.
```

## P1: Baseline and diff engine

```text
[x] Baseline model hashes
    Inspired by: supply-chain integrity checks.

[x] Baseline dataset fingerprints
    Inspired by: Evidently/TFDV/whylogs profile comparison.

[x] Baseline tokenizer/chat-template/LoRA metadata
    Inspired by: AI-specific supply-chain drift checks.

[ ] Changed-only scan mode
    Reference: Gitleaks/pre-commit fast local workflow.

[ ] Git diff aware baseline comparison
    Reference: CI scanners that compare PR state to base branch.

[x] Per-tensor model baseline
    Implemented for safetensors: tensor names, dtypes, shapes, offsets,
    byte lengths, SHA-256 hashes, NaN/Inf counts, min/max/mean, L2 norm,
    and zero-value ratio.
    Reference: safe model artifact scanning + drift profile comparison.

[ ] Source/domain baseline for RAG and datasets
    Reference: data drift/provenance tooling.
```

## P2: Rule platform

```text
[ ] Rule registry
    Reference: Semgrep rule registry.

[ ] Built-in YAML rule metadata
    Reference: Semgrep readable YAML rules.

[ ] User custom rules
    Reference: Semgrep custom rules.

[ ] Rule docs generation
    Reference: Semgrep rule pages and security scanner documentation.

[ ] Golden JSON/SARIF snapshots per rule
    Reference: compiler/static-analysis test fixtures.
```

## P2: Dynamic evaluation, later

```text
[ ] ceres eval .
    Reference: promptfoo eval workflow.

[ ] ceres redteam .
    Reference: garak / promptfoo / PyRIT.

[ ] Probe/detector plugin API
    Reference: garak probes and detectors.

[ ] Optional prompt injection dynamic tests
    Reference: promptfoo red-team cases and PyRIT orchestration.
```

This is intentionally not MVP. Static repo scanning is the wedge.

---

# 29. Revised product direction: pre-production AI security layer

This section overrides any earlier broad-scanner instinct in this document.

## Product boundary

Ceres should be:

```text
pre-production security layer for AI systems.
```

Ceres should not be:

```text
generic secrets scanner
generic dependency scanner
generic SAST scanner
generic repo leak detector
```

Skylos already owns generic secrets/leaks. Competing there would split focus and
create a worse product. Ceres should integrate with or point to Skylos when that
surface matters, but Ceres should win on AI-specific model integrity and
poisoning-risk detection.

Ceres is broader than only LLMs. It should cover the AI-specific attack surfaces
that appear before an AI system reaches production:

```text
computer vision models
LLMs
embedding models
rerankers
RAG corpora and indexes
agents
tools
MCP servers and tool manifests
datasets
tokenizers and processors
model adapters such as LoRA
AI-BOM / model bill of materials
```

The right mental model:

```text
Ceres is a pre-production AI security gate.
Skylos is the generic secrets/leaks scanner.
```

## AI surface coverage matrix

The product should be organized by AI surface, not by generic repo-security
category.

```text
Computer vision
  Scan: model artifacts, processors, labels/classes, dataset manifests,
  image dataset provenance, tensor/layer baseline drift.
  Risks: poisoned training data, swapped classifier head, unexpected labels,
  unsafe serialization, untrusted model source.

LLMs
  Scan: model artifacts, tokenizers, special tokens, chat templates, adapters,
  model loading code, revision pins, tensor/layer baseline drift.
  Risks: trust_remote_code, unsafe pickle formats, tokenizer backdoors,
  chat-template injection, adapter/base mismatch, unpinned model revisions.

Embedding models / rerankers
  Scan: model artifacts, revision pins, embedding config, vector index metadata,
  dataset/RAG source provenance.
  Risks: embedding model swap, index built from untrusted docs, retrieval drift,
  source-domain poisoning.

RAG
  Scan: corpus files, hidden HTML, instruction-like text, source metadata,
  owner metadata, domain allowlists, vector index manifests.
  Risks: indirect prompt injection, poisoned docs, untrusted external sources,
  stale indexes.

Agents
  Scan: agent configs, planner settings, tool routing, permissions,
  confirmation policy, memory/store settings.
  Risks: excessive agency, no approval for sensitive actions, unsafe tool
  routing, unsafe memory writes.

Tools
  Scan: tool manifests, allowlists, shell/browser/file/network permissions,
  OpenAPI specs, tool schemas.
  Risks: unrestricted shell, unrestricted browser, file write without policy,
  broad network/tool scopes.

MCP
  Scan: MCP server manifests/configs, exposed tools/resources/prompts,
  transport config, command launch config, allowlists.
  Risks: overbroad exposed tools, local command execution, unsafe resources,
  prompt/tool injection through server-provided context.

Datasets
  Scan: manifests, hashes, schemas, source allowlists, duplicates, label drift,
  rare trigger repetition.
  Risks: poisoning indicators, stale manifests, unknown source, label shifts,
  trigger floods.

AI-BOM
  Scan/generate: models, datasets, prompts, RAG indexes, embedding models,
  adapters, tools, MCP servers.
  Risks: missing traceability, unknown artifacts, poor incident response.
```

## What Ceres owns

Core ownership:

```text
model artifacts
model serialization risk
model provenance
model revision pinning
model hashes
per-tensor/layer baselines
computer vision model metadata and weight integrity
LLM model metadata and weight integrity
embedding/reranker model integrity
tokenizers
image processors / feature extractors
special tokens
chat templates
LoRA adapters
AI-BOM model/dataset/prompt inventory
dataset poisoning-risk indicators
RAG corpus prompt-injection indicators
agent plans/configs
tool manifests and tool allowlists
MCP server manifests and exposed capabilities
AI agent tool configuration when it affects model behavior/safety
```

Secondary ownership:

```text
AI dependency context only where it affects model loading/runtime integrity
AI config policy only where it affects model source, model execution, tools, RAG,
or dataset provenance
```

Not owned:

```text
generic secret detection
generic credential leakage
generic vulnerable dependency management
generic Docker hardening
generic code style/SAST
generic cloud/IaC security
```

## Product message

Use this:

```text
Ceres detects AI-specific security risks before AI systems reach production.
```

Avoid this:

```text
Ceres finds all repo security issues.
```

Better positioning:

```text
ModelScan-style safe artifact scanning + Semgrep-style developer workflow +
dataset/RAG poisoning indicators + agent/tool/MCP policy + Ceres AI-BOM.
```

## Immediate implementation priority

The next implementation should be:

```text
Safetensors tensor/layer baseline scanning.
```

Reason:

```text
It is model-specific.
It does not overlap with Skylos.
It creates a defensible Ceres wedge.
It turns "scan model files" into something more useful than extension checks.
It supports the user's concern: "I do not know if a layer is poisoned."
It becomes the shared foundation for LLMs, computer vision models, embedding
models, rerankers, and adapters.
```

Important wording:

```text
Ceres should not say "this layer is poisoned."
Ceres should say "this tensor/layer changed unexpectedly" or
"this tensor/layer has poisoning-risk indicators."
```

---

# 30. Detailed implementation plan: safetensors tensor/layer scanner

## Goal

Add safe, static inspection for `.safetensors` model files.

The scanner should:

```text
read safetensors metadata without executing code
capture tensor names, dtypes, shapes, offsets, and hashes
store this information in .ceres/baseline.json
compare future scans against the baseline
emit model-specific findings for unexpected tensor/layer changes
```

## Why safetensors first

Safetensors is the right first target because:

```text
it is common in modern AI model repos
it is designed as a safer alternative to pickle-backed formats
its file structure supports metadata inspection without arbitrary code execution
it gives us model-layer visibility without importing the model
```

This follows the core Ceres principle:

```text
never import model files
never deserialize unsafely
never execute model code
```

## New files to add

```text
ceres/analyzers/model/safetensors_static.py
ceres/analyzers/model/tensor_baseline.py
tests/test_model_tensors.py
examples/model-integrity-repo/
```

## Baseline schema

Extend `.ceres/baseline.json`:

```json
{
  "models": {
    "models/adapter.safetensors": {
      "sha256": "...",
      "format": "safetensors",
      "tensors": {
        "model.layers.0.self_attn.q_proj.weight": {
          "dtype": "F16",
          "shape": [4096, 4096],
          "offsets": [0, 33554432],
          "sha256": "...",
          "byte_length": 33554432
        }
      },
      "tensor_count": 291,
      "total_tensor_bytes": 1234567890
    }
  }
}
```

## New rules

Implemented:

```text
ceres.model.tensor.added
ceres.model.tensor.removed
ceres.model.tensor.shape_changed
ceres.model.tensor.dtype_changed
ceres.model.tensor.hash_drift
ceres.model.tensor.nan_or_inf
ceres.model.tensor.norm_drift
ceres.model.tensor.sparsity_drift
ceres.model.tensor.range_anomaly
ceres.model.tensor.suspicious_name
ceres.model.safetensors.header_invalid
ceres.model.safetensors.header_oversized
```

Implement later:

```text
ceres.model.tensor.outlier_layer
ceres.model.onnx.metadata_anomaly
ceres.model.gguf.metadata_anomaly
```

## Rule semantics

```text
ceres.model.tensor.added
  Trigger: tensor exists now but did not exist in baseline.
  Severity: medium by default, high for sensitive layer patterns.
  Message: "New tensor/layer appeared compared with baseline."

ceres.model.tensor.removed
  Trigger: tensor existed in baseline but not in current model.
  Severity: high.
  Message: "Tensor/layer disappeared compared with baseline."

ceres.model.tensor.shape_changed
  Trigger: tensor name exists in both baseline and current file, but shape differs.
  Severity: high.
  Message: "Tensor/layer shape changed compared with baseline."

ceres.model.tensor.dtype_changed
  Trigger: dtype differs.
  Severity: medium or high.
  Message: "Tensor/layer dtype changed compared with baseline."

ceres.model.tensor.hash_drift
  Trigger: dtype and shape are same, but tensor byte hash differs.
  Severity: medium.
  Message: "Tensor bytes changed while shape and dtype stayed constant."

ceres.model.tensor.suspicious_name
  Trigger: tensor name contains high-risk strings like backdoor, trigger,
  override, admin, jailbreak, secret, malicious.
  Severity: low alone, medium/high if combined with added/hash_changed.
  Message: "Tensor/layer name contains suspicious marker text."

ceres.model.tensor.nan_or_inf
  Trigger: tensor values include NaN or +/-Inf.
  Severity: high.
  Message: "Tensor contains NaN or infinite values."

ceres.model.tensor.norm_drift
  Trigger: tensor L2 norm changes beyond policy threshold compared with baseline.
  Severity: medium.
  Message: "Tensor L2 norm changed sharply compared with baseline."

ceres.model.tensor.sparsity_drift
  Trigger: zero-value ratio changes beyond policy threshold compared with baseline.
  Severity: medium.
  Message: "Tensor sparsity changed sharply compared with baseline."

ceres.model.tensor.range_anomaly
  Trigger: tensor min/max absolute value exceeds policy limit.
  Severity: medium.
  Message: "Tensor value range exceeds the configured absolute-value limit."

ceres.model.safetensors.header_invalid
  Trigger: safetensors header cannot be parsed.
  Severity: high.
  Message: "Safetensors file has invalid or unreadable metadata."

ceres.model.safetensors.header_oversized
  Trigger: header length exceeds policy cap.
  Severity: high.
  Message: "Safetensors metadata header is unusually large."
```

## Safety limits

Add policy fields:

```yaml
model_policy:
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
```

Design choices:

```text
hash tensor bytes by streaming from offsets
do not load tensors into RAM
do not import torch
do not use transformers
do not execute any model code
enforce header and tensor size limits
surface skipped hashes as low/medium findings if policy requires full coverage
```

## Implementation steps

1. Parse safetensors header safely.

```text
read first 8 bytes as little-endian unsigned header length
reject header length > max_safetensors_header_bytes
read header JSON
validate each tensor entry has dtype, shape, data_offsets
reject negative offsets, reversed offsets, offsets outside file size
ignore __metadata__ for tensor list but preserve safe metadata fields
```

2. Build tensor inventory.

```text
TensorInfo:
  name
  dtype
  shape
  offsets
  byte_length
  sha256 optional
```

3. Hash tensor bytes.

```text
seek to tensor start
read byte ranges in chunks
hash only that tensor range
skip hash if tensor exceeds max_tensor_hash_bytes unless policy permits
```

4. Store tensor baseline.

```text
extend baseline/store.py so build_baseline() includes safetensors tensor info
```

5. Compare during scan.

```text
current tensor map vs baseline tensor map
added
removed
shape changed
dtype changed
hash changed
suspicious names
```

6. Add tests.

```text
create minimal safetensors fixture by writing header + bytes manually
test baseline captures tensor metadata
test added tensor finding
test removed tensor finding
test shape changed finding
test dtype changed finding
test hash changed finding
test invalid header finding
```

7. Add docs.

```text
README model layer scanning section
plan.md checklist status
example repo with safe tiny safetensors file
```

## Acceptance criteria

```text
ceres baseline examples/model-integrity-repo
  writes tensor metadata into .ceres/baseline.json

ceres scan examples/model-integrity-repo --baseline .ceres/baseline.json
  passes when unchanged

mutating tensor bytes without changing shape
  emits ceres.model.tensor.hash_drift

changing shape in header
  emits ceres.model.tensor.shape_changed

adding tensor
  emits ceres.model.tensor.added

removing tensor
  emits ceres.model.tensor.removed

invalid safetensors header
  emits ceres.model.safetensors.header_invalid

tensor contains NaN or +/-Inf
  emits ceres.model.tensor.nan_or_inf

tensor L2 norm changes sharply from baseline
  emits ceres.model.tensor.norm_drift

tensor zero-value ratio changes sharply from baseline
  emits ceres.model.tensor.sparsity_drift

tensor absolute value exceeds policy limit
  emits ceres.model.tensor.range_anomaly
```

## Current implementation update

The next high-value item from the priority list is now implemented:

```text
[x] Safe safetensors tensor stats
    Files:
      ceres/analyzers/model/safetensors_static.py
      ceres/analyzers/model/scanner.py
      ceres/config.py
      tests/test_model_tensors.py
    Rules:
      ceres.model.tensor.nan_or_inf
      ceres.model.tensor.norm_drift
      ceres.model.tensor.sparsity_drift
      ceres.model.tensor.range_anomaly
    Why this matters:
      Poisoned or corrupted model weights can be byte-different while keeping
      the same tensor names, shapes, and dtypes. Compact statistics give Ceres
      an AI-model-specific signal beyond generic file hashes.
    What was adapted:
      No code, rule IDs, or rule bodies were copied from upstream repos.
      The implementation uses the public safetensors file format and our own
      streaming stat logic, thresholds, messages, and Ceres-owned rule IDs.
    Inspiration only:
      safetensors: safe file layout and metadata fields. [21]
      whylogs: single-pass lightweight profiling mindset. [28]
      Evidently/TFDV: compare current state to reference/baseline and emit drift. [29][30]
```

Next priorities:

```text
1. ONNX/GGUF metadata scanners
   Add safe metadata parsing for model formats teams already ship.

2. Cross-layer outlier scoring
   Compare tensor stats across similar layer families, not only against a
   baseline. Useful when there is no clean baseline yet.

3. RAG/tool/MCP hardening
   Add AI-system checks around tool contracts, retrieval boundaries, and MCP
   server capability manifests.

4. Optional dynamic eval integration
   Keep this downstream of static scan. Use garak/promptfoo/PyRIT style probe
   architecture only when the user opts into runtime testing.
```

## What not to do

Do not implement these in Ceres as core features:

```text
generic repo secret scanning
generic leak detection
generic credential scanning
generic dependency CVE management as the product wedge
```

If needed, later:

```text
ceres scan . --with-skylos
```

But the default Ceres path should stay focused on AI models and AI artifacts.

[1]: https://github.com/protectai/modelscan?utm_source=chatgpt.com "protectai/modelscan: Protection against Model ..."
[2]: https://semgrep.dev/docs/writing-rules/overview?utm_source=chatgpt.com "Write rules"
[3]: https://www.promptfoo.dev/docs/model-audit/?utm_source=chatgpt.com "ModelAudit - Static Security Scanner for ML Models"
[4]: https://github.com/mmaitre314/picklescan?utm_source=chatgpt.com "mmaitre314/picklescan: Security scanner detecting Python ..."
[5]: https://github.com/NVIDIA/garak/blob/main/FAQ.md?utm_source=chatgpt.com "garak/FAQ.md at main"
[6]: https://github.com/promptfoo/promptfoo/blob/main/site/docs/red-team/configuration.md?utm_source=chatgpt.com "promptfoo/site/docs/red-team/configuration.md at main"
[7]: https://github.com/microsoft/PyRIT?utm_source=chatgpt.com "Python Risk Identification Tool for generative AI (PyRIT)"
[8]: https://github.com/gitleaks/gitleaks?utm_source=chatgpt.com "Find secrets with Gitleaks"
[9]: https://pypi.org/project/pip-audit/?utm_source=chatgpt.com "pip-audit"
[10]: https://docs.cleanlab.ai/stable/tutorials/datalab/text.html?utm_source=chatgpt.com "Detecting Issues in a Text Dataset with Datalab"
[11]: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github?utm_source=chatgpt.com "Uploading a SARIF file to GitHub"
[12]: https://pytorch.org/projects/safetensors/?utm_source=chatgpt.com "Safetensors"
[13]: https://owasp.org/www-project-machine-learning-security-top-10/?utm_source=chatgpt.com "OWASP Machine Learning Security Top Ten"
[14]: https://genai.owasp.org/llmrisk/llm01-prompt-injection/?utm_source=chatgpt.com "LLM01:2025 Prompt Injection - OWASP Gen AI Security Project"
[15]: https://scorecard.dev/?utm_source=chatgpt.com "OpenSSF Scorecard"
[16]: https://www.ntia.gov/page/software-bill-materials "Software bill of materials overview"
[17]: https://csrc.nist.gov/pubs/ai/100/2/e2025/final?utm_source=chatgpt.com "AI 100-2 E2025, Adversarial Machine Learning: A Taxonomy ..."
[18]: https://atlas.mitre.org/?utm_source=chatgpt.com "MITRE ATLAS™"
[19]: https://pre-commit.com/?utm_source=chatgpt.com "pre-commit"
[20]: https://docs.python.org/3/library/ast.html "ast — Abstract syntax trees"
[21]: https://huggingface.co/docs/safetensors/index "Safetensors"
[22]: https://huggingface.co/docs/hub/model-cards "Model cards"
[23]: https://www.rust-lang.org/ "Rust Programming Language"
[24]: https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html "What Is Ownership? - The Rust Programming Language"
[25]: https://docs.astral.sh/ruff/ "Ruff"
[26]: https://pyo3.rs/main/doc/pyo3/ "PyO3"
[27]: https://github.com/PyO3/maturin "maturin"
[28]: https://docs.whylogs.com/en/latest/features/profiling.html "whylogs profiling"
[29]: https://docs.evidentlyai.com/metrics/preset_data_drift "Evidently Data Drift"
[30]: https://www.tensorflow.org/tfx/tutorials/data_validation/tfdv_basic "TensorFlow Data Validation"
