from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from ceres.analyzers.base import AnalyzerContext
from ceres.analyzers.data.drift import jensen_shannon
from ceres.analyzers.data.fingerprint import fingerprint
from ceres.findings.model import Evidence, Finding, FrameworkMap, Layer, Severity


def run(ctx: AnalyzerContext) -> list[Finding]:
    findings: list[Finding] = []
    pol = ctx.policy.data_policy
    baseline_datasets = (ctx.baseline or {}).get("datasets", {}) if ctx.baseline else {}

    manifests = _load_manifests(ctx)
    covered: set[str] = set()
    for manifest_path, manifest in manifests.items():
        for entry in manifest.get("dataset", {}).get("files", []) or []:
            p = entry.get("path")
            if p:
                covered.add(p)
        findings.extend(_validate_manifest(manifest, manifest_path, ctx))

    for dataset in ctx.inventory.datasets:
        rel = ctx.rel(dataset)
        findings.extend(_check_dataset(dataset, rel, ctx, pol, baseline_datasets, manifests, covered))

    return findings


def _load_manifests(ctx: AnalyzerContext) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in ctx.inventory.data_manifests:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(data, dict):
            out[ctx.rel(path)] = data
    return out


def _validate_manifest(manifest: dict, rel: str, ctx: AnalyzerContext) -> list[Finding]:
    out: list[Finding] = []
    ds = manifest.get("dataset") if isinstance(manifest, dict) else None
    if not isinstance(ds, dict):
        return out
    required = ["name", "version", "files"]
    if ctx.policy.data_policy.require_owner:
        required.append("owner")
    missing = [k for k in required if not ds.get(k)]
    if missing:
        out.append(
            Finding(
                rule_id="ceres.dataset.manifest_incomplete",
                severity=Severity.MEDIUM,
                layer=Layer.DATA,
                file=rel,
                message=f"Dataset manifest missing required keys: {', '.join(missing)}.",
                recommendation="Populate name, version, owner, and files entries.",
            )
        )
    return out


def _check_dataset(
    dataset: Path,
    rel: str,
    ctx: AnalyzerContext,
    pol,
    baseline_datasets: dict,
    manifests: dict[str, dict],
    covered: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    manifest_entry = _lookup_manifest_entry(rel, manifests)

    if pol.require_manifest and manifest_entry is None and rel not in covered:
        findings.append(
            Finding(
                rule_id="ceres.dataset.manifest_missing",
                severity=Severity.HIGH,
                layer=Layer.DATA,
                file=rel,
                message="Dataset has no dataset.yaml manifest entry.",
                recommendation="Add the dataset to dataset.yaml with owner, source, hash, and schema.",
                frameworks=FrameworkMap(owasp_llm=("LLM03",), owasp_ml=("ML02",)),
            )
        )

    sha = _sha256(dataset)
    if pol.require_hashes:
        expected = (manifest_entry or {}).get("sha256")
        if expected is None and manifest_entry is not None:
            findings.append(
                Finding(
                    rule_id="ceres.dataset.hash_missing",
                    severity=Severity.MEDIUM,
                    layer=Layer.DATA,
                    file=rel,
                    message="Manifest entry for this dataset has no sha256.",
                    recommendation="Populate sha256 to detect unauthorized changes.",
                )
            )
        elif expected is not None and expected != sha:
            findings.append(
                Finding(
                    rule_id="ceres.dataset.hash_drift",
                    severity=Severity.HIGH,
                    layer=Layer.DATA,
                    file=rel,
                    message="Dataset hash differs from manifest declaration.",
                    recommendation="Re-validate the dataset and update the manifest in the same change.",
                    evidence=Evidence(extra={"expected_sha256": expected, "actual_sha256": sha}),
                    frameworks=FrameworkMap(owasp_ml=("ML02",)),
                )
            )

    source_allowlist = pol.allowed_sources or (manifest_entry or {}).get("source_allowlist") or []
    if source_allowlist and manifest_entry is not None:
        src = (manifest_entry.get("source") or "").strip()
        if src and not any(src.startswith(prefix) for prefix in source_allowlist):
            findings.append(
                Finding(
                    rule_id="ceres.dataset.source_unapproved",
                    severity=Severity.HIGH,
                    layer=Layer.DATA,
                    file=rel,
                    message=f"Dataset source '{src}' is not in the allowed list.",
                    recommendation="Either add the source to data_policy.allowed_sources or move the dataset to an approved location.",
                    frameworks=FrameworkMap(owasp_llm=("LLM03",), owasp_ml=("ML02",)),
                )
            )

    fp = fingerprint(dataset)
    if fp is None:
        return findings

    if fp.duplicate_rate > pol.max_duplicate_rate:
        findings.append(
            Finding(
                rule_id="ceres.dataset.duplicate_flood",
                severity=Severity.MEDIUM,
                layer=Layer.DATA,
                file=rel,
                message=(
                    f"Duplicate rate {fp.duplicate_rate:.1%} exceeds policy threshold "
                    f"{pol.max_duplicate_rate:.1%}."
                ),
                recommendation="Deduplicate rows or investigate why duplicates were introduced.",
                evidence=Evidence(extra={"duplicate_rate": fp.duplicate_rate}),
                frameworks=FrameworkMap(owasp_ml=("ML02",)),
            )
        )

    baseline = baseline_datasets.get(rel)
    if baseline:
        prev_dist = baseline.get("label_distribution") or {}
        if prev_dist and fp.label_distribution:
            jsd = jensen_shannon(prev_dist, fp.label_distribution)
            if jsd > pol.max_label_jsd:
                findings.append(
                    Finding(
                        rule_id="ceres.dataset.label_distribution_drift",
                        severity=Severity.MEDIUM,
                        layer=Layer.DATA,
                        file=rel,
                        message=(
                            f"Label distribution JS divergence {jsd:.3f} exceeds threshold "
                            f"{pol.max_label_jsd:.3f}."
                        ),
                        recommendation="Compare new labels with the baseline; investigate large shifts.",
                        evidence=Evidence(extra={"jsd": jsd, "current": fp.label_distribution}),
                        frameworks=FrameworkMap(owasp_ml=("ML02",)),
                    )
                )

        baseline_top = set(baseline.get("top_ngrams") or [])
        new_top = set(fp.top_ngrams) - baseline_top
        suspicious_new = sorted(new_top)
        if baseline_top and len(suspicious_new) >= 5:
            findings.append(
                Finding(
                    rule_id="ceres.dataset.rare_phrase_repetition",
                    severity=Severity.MEDIUM,
                    layer=Layer.DATA,
                    file=rel,
                    message=(
                        f"{len(suspicious_new)} new high-frequency trigrams since baseline."
                    ),
                    recommendation="Sample rows containing the new trigrams and look for prompt-injection-style phrases.",
                    evidence=Evidence(extra={"new_trigrams_preview": suspicious_new[:10]}),
                    frameworks=FrameworkMap(owasp_llm=("LLM03",), owasp_ml=("ML02",)),
                )
            )

        prev_sha = baseline.get("sha256")
        if prev_sha and prev_sha != fp.sha256:
            manifest_sha = (manifest_entry or {}).get("sha256")
            if manifest_sha == prev_sha:
                findings.append(
                    Finding(
                        rule_id="ceres.dataset.manifest_stale_hash",
                        severity=Severity.HIGH,
                        layer=Layer.DATA,
                        file=rel,
                        message="Dataset file changed but manifest still references the old hash.",
                        recommendation="Recompute and update the manifest sha256 in the same change.",
                        frameworks=FrameworkMap(owasp_ml=("ML02",)),
                    )
                )

    return findings


def _lookup_manifest_entry(rel: str, manifests: dict[str, dict]) -> dict | None:
    for manifest in manifests.values():
        ds = manifest.get("dataset") or {}
        files = ds.get("files") or []
        for entry in files:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            if path and (path == rel or rel.endswith(path)):
                merged = dict(entry)
                merged.setdefault("source", ds.get("source"))
                merged.setdefault("source_allowlist", ds.get("source_allowlist"))
                return merged
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
