from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ceres.findings.model import Finding, Layer


class DiffError(RuntimeError):
    pass


@dataclass
class DiffContext:
    base_ref: str
    compare_ref: str
    git_root: Path
    scan_root: Path
    changed_files: set[str] = field(default_factory=set)
    deleted_files: set[str] = field(default_factory=set)
    changed_lines: dict[str, set[int]] = field(default_factory=dict)
    untracked_files: set[str] = field(default_factory=set)

    @property
    def changed_file_count(self) -> int:
        return len(self.changed_files | self.deleted_files)

    def to_dict(self, *, original_findings: int | None = None, filtered_findings: int | None = None) -> dict:
        payload: dict[str, object] = {
            "base_ref": self.base_ref,
            "compare_ref": self.compare_ref,
            "changed_file_count": self.changed_file_count,
            "changed_files": sorted(self.changed_files),
            "deleted_files": sorted(self.deleted_files),
            "untracked_files": sorted(self.untracked_files),
        }
        if original_findings is not None:
            payload["original_findings"] = original_findings
        if filtered_findings is not None:
            payload["filtered_findings"] = filtered_findings
        return payload


_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

_BOM_RELEVANT_PREFIXES = (
    "models/",
    "model/",
    "data/",
    "datasets/",
)
_BOM_RELEVANT_NAMES = {"ai-bom.json", "dataset.yaml", "dataset.yml"}
_BOM_RELEVANT_SUFFIXES = {
    ".csv",
    ".jsonl",
    ".parquet",
    ".safetensors",
    ".onnx",
    ".gguf",
    ".pt",
    ".pth",
    ".bin",
    ".ckpt",
    ".pkl",
    ".pickle",
    ".joblib",
}


def collect_git_diff(root: Path, base_ref: str) -> DiffContext:
    root = root.expanduser().resolve()
    git_root = _git_root(root)
    compare_ref = _merge_base(git_root, base_ref)
    ctx = DiffContext(
        base_ref=base_ref,
        compare_ref=compare_ref,
        git_root=git_root,
        scan_root=root,
    )

    _merge_name_status(ctx, _git(git_root, "diff", "--name-status", "--find-renames", compare_ref, "HEAD"))
    _merge_line_diff(ctx, _git(git_root, "diff", "--unified=0", "--no-ext-diff", compare_ref, "HEAD"))

    _merge_name_status(ctx, _git(git_root, "diff", "--cached", "--name-status", "--find-renames"))
    _merge_line_diff(ctx, _git(git_root, "diff", "--cached", "--unified=0", "--no-ext-diff"))

    _merge_name_status(ctx, _git(git_root, "diff", "--name-status", "--find-renames"))
    _merge_line_diff(ctx, _git(git_root, "diff", "--unified=0", "--no-ext-diff"))

    _merge_untracked(ctx)
    return ctx


def filter_findings_for_diff(findings: list[Finding], diff: DiffContext) -> list[Finding]:
    return [finding for finding in findings if finding_in_diff(finding, diff)]


def finding_in_diff(finding: Finding, diff: DiffContext) -> bool:
    if finding.rule_id == "ceres.engine.analyzer_failed":
        return True

    if finding.layer == Layer.BOM and _has_bom_relevant_change(diff):
        return True

    if finding.rule_id == "ceres.policy.waiver_expired":
        return "ceres.yml" in diff.changed_files or finding.file in diff.changed_files

    if finding.file not in diff.changed_files:
        return False

    if finding.line is None:
        return True

    lines = diff.changed_lines.get(finding.file)
    if lines is None:
        return True
    return finding.line in lines


def _git_root(root: Path) -> Path:
    try:
        out = _git(root, "rev-parse", "--show-toplevel").strip()
    except DiffError as e:
        raise DiffError(f"{root} is not inside a git repository") from e
    git_root = Path(out).resolve()
    try:
        root.relative_to(git_root)
    except ValueError as e:
        raise DiffError(f"{root} is not inside git root {git_root}") from e
    return git_root


def _merge_base(git_root: Path, base_ref: str) -> str:
    try:
        return _git(git_root, "merge-base", base_ref, "HEAD").strip()
    except DiffError:
        _git(git_root, "rev-parse", "--verify", base_ref)
        return base_ref


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise DiffError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout


def _merge_name_status(ctx: DiffContext, text: str) -> None:
    for raw in text.splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        status = parts[0]
        if status.startswith(("R", "C")) and len(parts) >= 3:
            old_path = _to_scan_rel(ctx, parts[1])
            new_path = _to_scan_rel(ctx, parts[2])
            if old_path is not None:
                ctx.deleted_files.add(old_path)
            if new_path is not None:
                ctx.changed_files.add(new_path)
            continue
        if len(parts) < 2:
            continue
        path = _to_scan_rel(ctx, parts[1])
        if path is None:
            continue
        if status == "D":
            ctx.deleted_files.add(path)
        else:
            ctx.changed_files.add(path)


def _merge_line_diff(ctx: DiffContext, text: str) -> None:
    current_path: str | None = None
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":
                current_path = None
            elif target.startswith("b/"):
                current_path = _to_scan_rel(ctx, target[2:])
            else:
                current_path = _to_scan_rel(ctx, target)
            continue
        if not raw.startswith("@@ ") or current_path is None:
            continue
        match = _HUNK_RE.search(raw)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count <= 0:
            continue
        ctx.changed_lines.setdefault(current_path, set()).update(range(start, start + count))


def _merge_untracked(ctx: DiffContext) -> None:
    text = _git(ctx.git_root, "ls-files", "--others", "--exclude-standard")
    for raw in text.splitlines():
        path = _to_scan_rel(ctx, raw.strip())
        if path is None:
            continue
        ctx.changed_files.add(path)
        ctx.untracked_files.add(path)
        line_count = _line_count(ctx.scan_root / path)
        if line_count:
            ctx.changed_lines[path] = set(range(1, line_count + 1))


def _to_scan_rel(ctx: DiffContext, git_path: str) -> str | None:
    absolute = (ctx.git_root / git_path).resolve()
    try:
        rel = absolute.relative_to(ctx.scan_root)
    except ValueError:
        return None
    return rel.as_posix()


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return 0


def _has_bom_relevant_change(diff: DiffContext) -> bool:
    for path in diff.changed_files | diff.deleted_files:
        p = Path(path)
        if path.startswith(_BOM_RELEVANT_PREFIXES):
            return True
        if p.name in _BOM_RELEVANT_NAMES or p.suffix.lower() in _BOM_RELEVANT_SUFFIXES:
            return True
    return False
