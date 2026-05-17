from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class DatasetFingerprint:
    path: str
    sha256: str
    row_count: int
    duplicate_rate: float
    label_column: str | None
    label_distribution: dict[str, float]
    top_ngrams: list[str]
    columns: list[str]


_LABEL_COLUMN_CANDIDATES = ("label", "labels", "category", "intent", "class", "target")
_TEXT_COLUMN_CANDIDATES = ("text", "prompt", "content", "input", "question", "message", "body")


def fingerprint(path: Path, *, max_rows: int = 200_000) -> DatasetFingerprint | None:
    suffix = path.suffix.lower()
    try:
        if suffix in {".csv", ".tsv"}:
            rows = list(_read_delimited(path, max_rows))
        elif suffix in {".jsonl", ".ndjson"}:
            rows = list(_read_jsonl(path, max_rows))
        elif suffix == ".parquet":
            rows = list(_read_parquet(path, max_rows))
        else:
            return None
    except OSError:
        return None
    if not rows:
        return None
    cols = list(rows[0].keys())
    label_col = _pick_first(cols, _LABEL_COLUMN_CANDIDATES)
    text_col = _pick_first(cols, _TEXT_COLUMN_CANDIDATES)

    sig = Counter()
    label_counter: Counter[str] = Counter()
    ngram_counter: Counter[str] = Counter()

    for row in rows:
        text = ""
        if text_col is not None:
            text = str(row.get(text_col, ""))
        elif row:
            text = " ".join(str(v) for v in row.values())
        sig[hashlib.md5(text.strip().lower().encode("utf-8")).hexdigest()] += 1

        if label_col is not None:
            label_counter[str(row.get(label_col, ""))] += 1

        for ng in _trigrams(text.lower()):
            ngram_counter[ng] += 1

    row_count = len(rows)
    dup = sum(c - 1 for c in sig.values() if c > 1)
    dup_rate = dup / row_count if row_count else 0.0

    total_labels = sum(label_counter.values())
    label_dist = (
        {k: v / total_labels for k, v in label_counter.items()} if total_labels else {}
    )

    top_ngrams = [ng for ng, _ in ngram_counter.most_common(50)]

    return DatasetFingerprint(
        path=str(path),
        sha256=_sha256_file(path),
        row_count=row_count,
        duplicate_rate=dup_rate,
        label_column=label_col,
        label_distribution=label_dist,
        top_ngrams=top_ngrams,
        columns=cols,
    )


def _pick_first(cols: list[str], candidates: tuple[str, ...]) -> str | None:
    lower = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand in lower:
            return lower[cand]
    return None


def _trigrams(text: str) -> Iterator[str]:
    toks = [t for t in text.split() if t]
    for i in range(len(toks) - 2):
        yield " ".join(toks[i : i + 3])


def _read_delimited(path: Path, max_rows: int) -> Iterator[dict]:
    delim = "\t" if path.suffix.lower() == ".tsv" else ","
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f, delimiter=delim)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            yield row


def _read_jsonl(path: Path, max_rows: int) -> Iterator[dict]:
    with path.open(encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_rows:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _read_parquet(path: Path, max_rows: int) -> Iterator[dict]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except ImportError:
        return iter([])
    table = pq.read_table(path)
    rows = table.to_pylist()
    return iter(rows[:max_rows])


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
