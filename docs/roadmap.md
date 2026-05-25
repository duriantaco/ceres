# Roadmap

Ceres is intentionally focused on AI pre-production security. Generic leak
scanning and repo-history secret detection should stay in Skylos.

## Implemented

- Python AI-SAST rules for model loading and unsafe deserialization
- config checks for model source, revision pinning, and shell-capable tools
- static pickle opcode inspection
- safetensors header validation
- safetensors tensor baseline, hashes, and numeric stats
- tokenizer, chat-template, and LoRA base-model drift
- dataset manifest, hash, source, duplicate, label drift, and rare phrase checks
- RAG prompt-injection and covert-content checks
- RAG ingestion and retrieval permission-flow heuristics
- eval and safety-config drift checks
- MCP/tool description poisoning checks and tool metadata baseline drift
- AI-BOM generation and coverage checks
- JSON, SARIF, and CLI reports
- waiver expiry checks

## Next Highest-Value Work

1. ONNX and GGUF metadata scanners.
2. Cross-layer outlier scoring when no clean baseline exists.
3. Broader MCP server command, scope, and permission checks.
4. JavaScript/TypeScript AI SDK rules.
5. Optional dynamic probe integration for runtime evals.

## Non-Goals

- replacing Skylos for secrets and leak detection
- broad generic SCA as the main product wedge
- executing or importing model artifacts during static scan
