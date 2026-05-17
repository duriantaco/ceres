from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from ceres.inventory.classifier import IGNORE_DIRS, classify


@dataclass
class Inventory:
    root: Path
    code: list[Path] = field(default_factory=list)
    prompts: list[Path] = field(default_factory=list)
    configs: list[Path] = field(default_factory=list)
    models: list[Path] = field(default_factory=list)
    datasets: list[Path] = field(default_factory=list)
    data_manifests: list[Path] = field(default_factory=list)
    rag_docs: list[Path] = field(default_factory=list)
    dependencies: list[Path] = field(default_factory=list)
    ci: list[Path] = field(default_factory=list)

    def all_paths(self) -> list[Path]:
        return [
            *self.code,
            *self.prompts,
            *self.configs,
            *self.models,
            *self.datasets,
            *self.data_manifests,
            *self.rag_docs,
            *self.dependencies,
            *self.ci,
        ]

    def summary(self) -> dict[str, int]:
        return {
            "code": len(self.code),
            "prompts": len(self.prompts),
            "configs": len(self.configs),
            "models": len(self.models),
            "datasets": len(self.datasets),
            "data_manifests": len(self.data_manifests),
            "rag_docs": len(self.rag_docs),
            "dependencies": len(self.dependencies),
            "ci": len(self.ci),
        }


def _read_gitignore_patterns(root: Path) -> list[str]:
    gi = root / ".gitignore"
    if not gi.exists():
        return []
    out: list[str] = []
    for line in gi.read_text(errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s.lstrip("/"))
    return out


def _is_ignored(rel: Path, patterns: list[str]) -> bool:
    s = str(rel)
    for p in patterns:
        if fnmatch.fnmatch(s, p) or fnmatch.fnmatch(rel.name, p):
            return True
        if p.endswith("/") and s.startswith(p):
            return True
    return False


def build_inventory(root: Path) -> Inventory:
    root = root.resolve()
    inv = Inventory(root=root)
    patterns = _read_gitignore_patterns(root)

    for path in _walk(root):
        rel = path.relative_to(root)
        if _is_ignored(rel, patterns):
            continue
        bucket = classify(path, root)
        if bucket is None:
            continue
        getattr(inv, bucket).append(path)

    return inv


def _walk(root: Path):
    for entry in root.iterdir():
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if entry.name in IGNORE_DIRS:
                continue
            yield from _walk(entry)
        elif entry.is_file():
            yield entry
