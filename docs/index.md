---
title: Ceres | Pre-production AI Security Scanner
description: Static security scanning for AI models, datasets, RAG corpora, prompts, agents, tools, MCP, and AI supply chain.
---

# Ceres

<div class="ceres-hero">
  <div class="ceres-hero__copy">
    <h1>Pre-production security for AI systems.</h1>
    <p>
      Ceres scans AI repos before models, prompts, datasets, RAG content, and
      agent tooling reach production. It is an AI security layer, not a generic
      leak scanner.
    </p>
    <div class="ceres-pill-row">
      <span class="ceres-pill">model artifacts</span>
      <span class="ceres-pill">tensor drift</span>
      <span class="ceres-pill">RAG injection</span>
      <span class="ceres-pill">agent tools</span>
      <span class="ceres-pill">AI-BOM</span>
    </div>
  </div>
  <div class="ceres-panel">
    <div class="ceres-stat">91 rules</div>
    <p>Static checks across code, models, datasets, evals, RAG, prompts, agent
    tools, supply chain, policy, and AI-BOM coverage.</p>
    <pre><code>ceres scan .
ceres baseline .
ceres bom . --out ai-bom.json</code></pre>
  </div>
</div>

## What Ceres Is For

Ceres is built for pull requests, pre-commit hooks, and CI gates on AI/ML
repositories. It looks for high-signal issues that normal SAST and SCA tools do
not understand:

<div class="ceres-signal-grid">
  <div class="ceres-signal">
    <strong>Model Integrity</strong>
    Unsafe loaders, pickle-backed artifacts, provenance gaps, safetensors header
    issues, GGUF/ONNX metadata drift, tensor/layer drift, and suspicious numeric
    stats.
  </div>
  <div class="ceres-signal">
    <strong>RAG And Prompt Risk</strong>
    Unsafe user-document indexing, missing retrieval filters, instruction-like
    corpus content, hidden markup, encoded payloads, invisible control
    characters, and unsafe system prompt templating.
  </div>
  <div class="ceres-signal">
    <strong>AI Supply Chain</strong>
    Dataset manifest drift, unapproved sources, dependency pinning gaps, AI-BOM
    coverage, eval/safety gate drift, and optional external scanner
    normalization.
  </div>
</div>

## Quick Start

```bash
pip install -e .
ceres init
ceres baseline .
ceres scan . --json-out ceres-report.json --sarif-out ceres.sarif
```

## Documentation Map

| Area | Start here |
|---|---|
| Run the scanner | [Install and Run](getting-started.md) |
| Understand checks | [What Ceres Catches](coverage.md) |
| All rule IDs | [Rule Catalog](rules.md) |
| Model/tensor scanning | [Model Security](model-security.md) |
| CI and Pages deployment | [CI and GitHub Pages](ci.md) |

## Product Boundary

Ceres is not trying to replace Skylos for generic secrets, credential leaks, or
repository history scanning. Those integrations can exist, but they are off by
default. The core Ceres wedge is pre-production AI security: models, datasets,
RAG, prompts, agents, tools, MCP-adjacent config, and AI supply chain.
