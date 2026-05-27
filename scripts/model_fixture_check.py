#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ceres.analyzers.model.gguf_static import inspect_gguf
from ceres.analyzers.model.onnx_static import inspect_onnx
from ceres.config import Policy
from ceres.runner import run_scan


@dataclass(frozen=True)
class Fixture:
    name: str
    kind: str
    url: str
    sha256: str
    expected: dict[str, Any]
    corruptions: list[dict[str, Any]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Ceres model parsers against pinned real model artifact fixtures."
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=REPO_ROOT / "examples" / "model-fixture-corpus.yml",
        help="YAML corpus with real model fixture URLs, hashes, and expected metadata.",
    )
    parser.add_argument("--workdir", type=Path, help="Directory for downloaded/corrupted fixtures.")
    parser.add_argument("--json-out", type=Path, help="Write validation results as JSON.")
    parser.add_argument("--keep-workdir", action="store_true", help="Keep temporary workdir when one is created.")
    args = parser.parse_args(argv)

    owned_tmp: tempfile.TemporaryDirectory[str] | None = None
    if args.workdir is None:
        owned_tmp = tempfile.TemporaryDirectory(prefix="ceres-model-fixtures-")
        workdir = Path(owned_tmp.name)
    else:
        workdir = args.workdir.resolve()
        workdir.mkdir(parents=True, exist_ok=True)

    try:
        fixtures = _load_corpus(args.corpus)
        results = [_check_fixture(fixture, workdir) for fixture in fixtures]
        failed = sum(1 for result in results if not result["passed"])
        payload = {
            "summary": {
                "fixtures": len(results),
                "passed": len(results) - failed,
                "failed": failed,
                "workdir": str(workdir),
            },
            "fixtures": results,
        }
        _print_summary(payload)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(payload, indent=2, sort_keys=True))
            print(f"Wrote {args.json_out}")
        return 1 if failed else 0
    finally:
        if owned_tmp is not None and not args.keep_workdir:
            owned_tmp.cleanup()


def _load_corpus(path: Path) -> list[Fixture]:
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, dict) or not isinstance(raw.get("fixtures"), list):
        raise SystemExit("corpus must contain a 'fixtures' list")
    fixtures = []
    for item in raw["fixtures"]:
        if not isinstance(item, dict):
            raise SystemExit("each fixture must be a mapping")
        try:
            fixtures.append(
                Fixture(
                    name=_required_str(item, "name"),
                    kind=_required_str(item, "kind"),
                    url=_required_str(item, "url"),
                    sha256=_required_str(item, "sha256"),
                    expected=item.get("expected") or {},
                    corruptions=item.get("corruptions") or [],
                )
            )
        except TypeError as e:
            raise SystemExit(str(e)) from e
    return fixtures


def _required_str(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise TypeError(f"fixture field {key!r} must be a non-empty string")
    return value


def _check_fixture(fixture: Fixture, workdir: Path) -> dict[str, Any]:
    fixture_dir = workdir / _slug(fixture.name)
    fixture_dir.mkdir(parents=True, exist_ok=True)
    artifact = fixture_dir / f"artifact.{fixture.kind}"
    failures: list[str] = []
    parser_payload: dict[str, Any] | None = None
    corrupt_results: list[dict[str, Any]] = []

    try:
        _download(fixture.url, artifact, fixture.sha256)
        result = _inspect(fixture.kind, artifact)
        if not result["ok"]:
            failures.append(f"parser failed: {result['error']}")
        else:
            parser_payload = result["baseline"]
            failures.extend(_compare_expected(fixture.expected, parser_payload))
        for corruption in fixture.corruptions:
            corrupt_results.append(_check_corruption(fixture, artifact, fixture_dir, corruption))
            if not corrupt_results[-1]["passed"]:
                failures.append(corrupt_results[-1]["message"])
    except Exception as e:  # noqa: BLE001
        failures.append(str(e))

    return {
        "name": fixture.name,
        "kind": fixture.kind,
        "passed": not failures,
        "failures": failures,
        "artifact": str(artifact),
        "expected": fixture.expected,
        "parsed": parser_payload,
        "corruptions": corrupt_results,
    }


def _download(url: str, artifact: Path, expected_sha256: str) -> None:
    if artifact.exists() and _sha256(artifact) == expected_sha256:
        return
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise RuntimeError(f"download hash mismatch for {url}: expected {expected_sha256}, got {actual}")
    artifact.write_bytes(data)


def _inspect(kind: str, artifact: Path) -> dict[str, Any]:
    if kind == "onnx":
        result = inspect_onnx(artifact)
    elif kind == "gguf":
        result = inspect_gguf(artifact)
    else:
        raise RuntimeError(f"unsupported fixture kind {kind!r}")
    return {
        "ok": result.ok,
        "error": result.error,
        "error_code": result.error_code,
        "baseline": result.info.to_baseline() if result.info is not None else None,
    }


def _compare_expected(expected: dict[str, Any], parsed: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key, expected_value in expected.items():
        actual_value = parsed.get(key)
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict):
                failures.append(f"{key}: expected mapping, got {actual_value!r}")
                continue
            for inner_key, inner_expected in expected_value.items():
                inner_actual = actual_value.get(inner_key)
                if inner_actual != inner_expected:
                    failures.append(
                        f"{key}.{inner_key}: expected {inner_expected!r}, got {inner_actual!r}"
                    )
        elif actual_value != expected_value:
            failures.append(f"{key}: expected {expected_value!r}, got {actual_value!r}")
    return failures


def _check_corruption(
    fixture: Fixture,
    artifact: Path,
    fixture_dir: Path,
    corruption: dict[str, Any],
) -> dict[str, Any]:
    expected_rule = corruption.get("expected_rule")
    if not isinstance(expected_rule, str):
        return {"passed": False, "message": f"{fixture.name}: corruption missing expected_rule"}
    if "truncate" in corruption:
        n = corruption["truncate"]
        if not isinstance(n, int) or n < 0:
            return {"passed": False, "message": f"{fixture.name}: invalid truncate value {n!r}"}
        corrupted = fixture_dir / f"corrupt-truncate-{n}.{fixture.kind}"
        corrupted.write_bytes(artifact.read_bytes()[:n])
    else:
        return {"passed": False, "message": f"{fixture.name}: unsupported corruption {corruption!r}"}

    repo = fixture_dir / f"scan-{corrupted.stem}"
    if repo.exists():
        shutil.rmtree(repo)
    model_dir = repo / "models"
    model_dir.mkdir(parents=True)
    shutil.copy2(corrupted, model_dir / corrupted.name)
    findings, _suppressed, _counts, _passed, _inv = run_scan(repo, _policy(), None, repo / "ai-bom.json")
    rule_ids = sorted({finding.rule_id for finding in findings})
    passed = expected_rule in rule_ids
    return {
        "passed": passed,
        "message": "" if passed else f"{fixture.name}: expected {expected_rule}, got {rule_ids}",
        "artifact": str(corrupted),
        "expected_rule": expected_rule,
        "rule_ids": rule_ids,
    }


def _policy() -> Policy:
    policy = Policy()
    policy.model_policy.require_known_source = False
    policy.dependency_policy.run_pip_audit = False
    policy.dependency_policy.run_gitleaks = False
    return policy


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned or "fixture"


def _print_summary(payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    print(
        f"Model fixture validation: {summary['passed']}/{summary['fixtures']} passed "
        f"(failed: {summary['failed']})"
    )
    print(f"Workdir: {summary['workdir']}")
    for fixture in payload["fixtures"]:
        status = "PASS" if fixture["passed"] else "FAIL"
        print(f"  {status} {fixture['name']} ({fixture['kind']})")
        for failure in fixture["failures"]:
            print(f"    {failure}")


if __name__ == "__main__":
    raise SystemExit(main())
