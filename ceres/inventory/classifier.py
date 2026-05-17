from __future__ import annotations

from pathlib import Path

CODE_EXTS = {".py", ".ipynb"}
PROMPT_HINT_DIRS = {"prompts", "prompt", "system_prompts"}
PROMPT_EXTS = {".txt", ".md", ".prompt", ".tmpl", ".j2"}
CONFIG_EXTS = {".yaml", ".yml", ".json", ".toml"}
CONFIG_NAME_HINTS = {
    "agent.yaml",
    "agent.yml",
    "tools.json",
    "tools.yaml",
    "tools.yml",
    "config.yaml",
    "config.yml",
    "langchain.yaml",
    "llamaindex.yaml",
    "workflow.yaml",
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
}

MODEL_EXTS = {
    ".pkl",
    ".pickle",
    ".pt",
    ".pth",
    ".bin",
    ".safetensors",
    ".onnx",
    ".h5",
    ".keras",
    ".pb",
    ".gguf",
    ".joblib",
    ".ckpt",
}
MODEL_NAME_HINTS = {
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
    "config.json",
    "adapter_config.json",
    "generation_config.json",
}

DATASET_EXTS = {".csv", ".tsv", ".jsonl", ".ndjson", ".parquet", ".arrow", ".feather"}
DATASET_DIR_HINTS = {"data", "datasets", "dataset", "training_data"}

RAG_DOC_EXTS = {".md", ".markdown", ".txt", ".html", ".htm", ".pdf"}
RAG_DIR_HINTS = {"docs", "doc", "kb", "knowledge_base", "rag", "corpus", "index_source"}

DEP_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
}

CI_NAMES = {".pre-commit-config.yaml"}
CI_DIR_HINTS = {".github", ".gitlab", ".circleci"}

DOCKERFILE_HINTS = {"Dockerfile", "dockerfile"}

IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "dist",
    "build",
    ".ceres",
}

DATA_MANIFEST_NAME = "dataset.yaml"


def classify(path: Path, repo_root: Path) -> str | None:
    name = path.name
    suffix = path.suffix.lower()
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        rel = path
    parts = {p.lower() for p in rel.parts[:-1]}

    if any(p in IGNORE_DIRS for p in parts) or name in IGNORE_DIRS:
        return None

    if name in DEP_NAMES:
        return "dependencies"
    if name in CI_NAMES or any(p in CI_DIR_HINTS for p in parts):
        return "ci"
    if name in DOCKERFILE_HINTS or suffix == ".dockerfile":
        return "ci"

    if suffix in MODEL_EXTS or name in MODEL_NAME_HINTS:
        return "models"

    if name == DATA_MANIFEST_NAME:
        return "data_manifests"

    if suffix in DATASET_EXTS:
        return "datasets"

    if any(p in DATASET_DIR_HINTS for p in parts) and suffix in {".csv", ".jsonl", ".tsv"}:
        return "datasets"

    if suffix in CODE_EXTS:
        return "code"

    # Configs that look agent/tool-shaped
    if name in CONFIG_NAME_HINTS:
        return "configs"

    if any(p in PROMPT_HINT_DIRS for p in parts):
        if suffix in PROMPT_EXTS or suffix == "":
            return "prompts"

    if any(p in RAG_DIR_HINTS for p in parts) and suffix in RAG_DOC_EXTS:
        return "rag_docs"

    if suffix in CONFIG_EXTS:
        return "configs"

    if suffix in {".md", ".markdown"}:
        # generic markdown at repo root: treat as rag only if under a hint dir;
        # otherwise skip to avoid noise on README.md
        return None

    return None
