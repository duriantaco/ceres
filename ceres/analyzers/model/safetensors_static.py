from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MAX_HEADER_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_TENSOR_HASH_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_TENSOR_STAT_BYTES = 256 * 1024 * 1024
DEFAULT_HASH_BLOCK_SIZE = 1024 * 1024

_DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E5M2": 1,
    "F8_E4M3": 1,
    "F8_E8M0": 1,
    "U16": 2,
    "I16": 2,
    "F16": 2,
    "BF16": 2,
    "U32": 4,
    "I32": 4,
    "F32": 4,
    "U64": 8,
    "I64": 8,
    "F64": 8,
}

_STRUCT_FORMATS = {
    "BOOL": "B",
    "U8": "B",
    "I8": "b",
    "U16": "H",
    "I16": "h",
    "U32": "I",
    "I32": "i",
    "U64": "Q",
    "I64": "q",
    "F16": "e",
    "F32": "f",
    "F64": "d",
}


@dataclass(frozen=True)
class TensorStats:
    count: int
    finite_count: int
    nan_count: int
    inf_count: int
    zero_count: int
    min: float | None
    max: float | None
    mean: float | None
    l2_norm: float | None
    zero_ratio: float | None

    def to_baseline(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "finite_count": self.finite_count,
            "nan_count": self.nan_count,
            "inf_count": self.inf_count,
            "zero_count": self.zero_count,
            "min": _json_float(self.min),
            "max": _json_float(self.max),
            "mean": _json_float(self.mean),
            "l2_norm": _json_float(self.l2_norm),
            "zero_ratio": _json_float(self.zero_ratio),
        }


@dataclass(frozen=True)
class TensorInfo:
    name: str
    dtype: str
    shape: tuple[int, ...]
    data_offsets: tuple[int, int]
    file_offsets: tuple[int, int]
    byte_length: int
    sha256: str | None = None
    stats: TensorStats | None = None

    def to_baseline(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "dtype": self.dtype,
            "shape": list(self.shape),
            "offsets": list(self.data_offsets),
            "byte_length": self.byte_length,
        }
        if self.sha256 is not None:
            out["sha256"] = self.sha256
        if self.stats is not None:
            out["stats"] = self.stats.to_baseline()
        return out


@dataclass(frozen=True)
class SafetensorsInfo:
    tensors: dict[str, TensorInfo]
    metadata: dict[str, str]
    tensor_count: int
    total_tensor_bytes: int
    header_bytes: int

    def to_baseline(self) -> dict[str, Any]:
        return {
            "format": "safetensors",
            "tensor_count": self.tensor_count,
            "total_tensor_bytes": self.total_tensor_bytes,
            "header_bytes": self.header_bytes,
            "metadata": self.metadata,
            "tensors": {name: tensor.to_baseline() for name, tensor in self.tensors.items()},
        }


@dataclass(frozen=True)
class SafetensorsParseResult:
    info: SafetensorsInfo | None = None
    error: str | None = None
    error_code: str | None = None

    @property
    def ok(self) -> bool:
        return self.info is not None and self.error is None


def inspect_safetensors(
    path: Path,
    *,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
    max_tensor_hash_bytes: int = DEFAULT_MAX_TENSOR_HASH_BYTES,
    max_tensor_stat_bytes: int = DEFAULT_MAX_TENSOR_STAT_BYTES,
    hash_block_size: int = DEFAULT_HASH_BLOCK_SIZE,
    stat_block_size: int = DEFAULT_HASH_BLOCK_SIZE,
    hash_tensors: bool = True,
    compute_stats: bool = True,
) -> SafetensorsParseResult:
    try:
        file_size = path.stat().st_size
        with path.open("rb") as f:
            prefix = f.read(8)
            if len(prefix) != 8:
                return _err("ceres.model.safetensors.header_invalid", "Safetensors file is smaller than 8 bytes.")
            header_len = struct.unpack("<Q", prefix)[0]
            if header_len > max_header_bytes:
                return _err(
                    "ceres.model.safetensors.header_oversized",
                    f"Safetensors header is {header_len} bytes, above configured limit {max_header_bytes}.",
                )
            if 8 + header_len > file_size:
                return _err("ceres.model.safetensors.header_invalid", "Safetensors header length exceeds file size.")
            header_bytes = f.read(header_len)
            if len(header_bytes) != header_len:
                return _err("ceres.model.safetensors.header_invalid", "Safetensors header is truncated.")
            if not header_bytes.startswith(b"{"):
                return _err("ceres.model.safetensors.header_invalid", "Safetensors header must begin with a JSON object.")
            try:
                header = json.loads(header_bytes.decode("utf-8").strip())
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                return _err("ceres.model.safetensors.header_invalid", f"Safetensors header is not valid JSON: {e}.")
            if not isinstance(header, dict):
                return _err("ceres.model.safetensors.header_invalid", "Safetensors header must decode to a JSON object.")

            data_start = 8 + header_len
            data_size = file_size - data_start
            parsed = _parse_header(header, data_start, data_size)
            if parsed.error:
                return parsed
            assert parsed.info is not None

            if hash_tensors or compute_stats:
                tensors = {}
                for name, tensor in parsed.info.tensors.items():
                    digest = None
                    stats = None
                    if tensor.byte_length <= max_tensor_hash_bytes:
                        digest = _hash_range(f, tensor.file_offsets[0], tensor.byte_length, hash_block_size)
                    if compute_stats and tensor.byte_length <= max_tensor_stat_bytes:
                        stats = _stats_range(
                            f,
                            tensor.file_offsets[0],
                            tensor.byte_length,
                            tensor.dtype,
                            stat_block_size,
                        )
                    tensors[name] = TensorInfo(
                        name=tensor.name,
                        dtype=tensor.dtype,
                        shape=tensor.shape,
                        data_offsets=tensor.data_offsets,
                        file_offsets=tensor.file_offsets,
                        byte_length=tensor.byte_length,
                        sha256=digest,
                        stats=stats,
                    )
                info = SafetensorsInfo(
                    tensors=tensors,
                    metadata=parsed.info.metadata,
                    tensor_count=parsed.info.tensor_count,
                    total_tensor_bytes=parsed.info.total_tensor_bytes,
                    header_bytes=parsed.info.header_bytes,
                )
                return SafetensorsParseResult(info=info)
            return parsed
    except OSError as e:
        return _err("ceres.model.safetensors.header_invalid", f"Unable to read safetensors file: {e}.")


def _parse_header(header: dict[str, Any], data_start: int, data_size: int) -> SafetensorsParseResult:
    metadata_raw = header.get("__metadata__", {})
    if metadata_raw is None:
        metadata_raw = {}
    if not isinstance(metadata_raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in metadata_raw.items()
    ):
        return _err("ceres.model.safetensors.header_invalid", "Safetensors __metadata__ must be a string-to-string map.")

    tensors: dict[str, TensorInfo] = {}
    for name, raw in header.items():
        if name == "__metadata__":
            continue
        if not isinstance(name, str) or not isinstance(raw, dict):
            return _err("ceres.model.safetensors.header_invalid", "Tensor entries must be JSON objects keyed by name.")
        dtype = raw.get("dtype")
        shape = raw.get("shape")
        offsets = raw.get("data_offsets")
        if not isinstance(dtype, str) or not isinstance(shape, list) or not isinstance(offsets, list):
            return _err("ceres.model.safetensors.header_invalid", f"Tensor '{name}' is missing dtype, shape, or data_offsets.")
        if dtype not in _DTYPE_BYTES:
            return _err("ceres.model.safetensors.header_invalid", f"Tensor '{name}' uses unsupported dtype '{dtype}'.")
        if len(offsets) != 2 or not all(isinstance(v, int) for v in offsets):
            return _err("ceres.model.safetensors.header_invalid", f"Tensor '{name}' has invalid data_offsets.")
        begin, end = offsets
        if begin < 0 or end < begin or end > data_size:
            return _err("ceres.model.safetensors.header_invalid", f"Tensor '{name}' has offsets outside the tensor buffer.")
        if not all(isinstance(dim, int) and dim >= 0 for dim in shape):
            return _err("ceres.model.safetensors.header_invalid", f"Tensor '{name}' has invalid shape values.")
        byte_length = end - begin
        expected = _expected_nbytes(dtype, tuple(shape))
        if expected is None or expected != byte_length:
            return _err(
                "ceres.model.safetensors.header_invalid",
                f"Tensor '{name}' byte length does not match dtype and shape.",
            )
        tensors[name] = TensorInfo(
            name=name,
            dtype=dtype,
            shape=tuple(shape),
            data_offsets=(begin, end),
            file_offsets=(data_start + begin, data_start + end),
            byte_length=byte_length,
        )

    offset_result = _validate_contiguous_offsets(tensors, data_size)
    if offset_result is not None:
        return offset_result

    total = sum(t.byte_length for t in tensors.values())
    return SafetensorsParseResult(
        info=SafetensorsInfo(
            tensors=tensors,
            metadata=dict(metadata_raw),
            tensor_count=len(tensors),
            total_tensor_bytes=total,
            header_bytes=data_start - 8,
        )
    )


def _expected_nbytes(dtype: str, shape: tuple[int, ...]) -> int | None:
    n = 1
    for dim in shape:
        n = _checked_mul(n, dim)
        if n is None:
            return None
    return _checked_mul(n, _DTYPE_BYTES[dtype])


def _checked_mul(a: int | None, b: int) -> int | None:
    if a is None:
        return None
    if b != 0 and a > (2**63 - 1) // b:
        return None
    return a * b


def _validate_contiguous_offsets(tensors: dict[str, TensorInfo], data_size: int) -> SafetensorsParseResult | None:
    start = 0
    for tensor in sorted(tensors.values(), key=lambda t: t.data_offsets):
        begin, end = tensor.data_offsets
        if begin != start or end < begin:
            return _err("ceres.model.safetensors.header_invalid", f"Tensor '{tensor.name}' leaves a gap or overlaps data.")
        start = end
    if start != data_size:
        return _err("ceres.model.safetensors.header_invalid", "Safetensors tensor metadata does not cover the full buffer.")
    return None


def _hash_range(f, start: int, length: int, block_size: int) -> str:
    h = hashlib.sha256()
    f.seek(start)
    remaining = length
    chunk_size = max(1, block_size)
    while remaining:
        chunk = f.read(min(chunk_size, remaining))
        if not chunk:
            break
        h.update(chunk)
        remaining -= len(chunk)
    return h.hexdigest()


def _stats_range(f, start: int, length: int, dtype: str, block_size: int) -> TensorStats | None:
    item_size = _DTYPE_BYTES.get(dtype)
    if item_size is None or item_size <= 0:
        return None
    if dtype not in _STRUCT_FORMATS and dtype != "BF16":
        return None

    acc = _StatsAccumulator()
    if length == 0:
        return acc.finish()

    f.seek(start)
    remaining = length
    chunk_size = _aligned_block_size(block_size, item_size)
    while remaining:
        read_size = min(chunk_size, remaining)
        read_size -= read_size % item_size
        if read_size <= 0:
            return None
        chunk = f.read(read_size)
        if len(chunk) != read_size:
            return None
        for value in _iter_tensor_values(dtype, chunk):
            acc.add(value)
        remaining -= read_size
    return acc.finish()


def _aligned_block_size(block_size: int, item_size: int) -> int:
    size = max(item_size, block_size)
    aligned = size - (size % item_size)
    return aligned if aligned >= item_size else item_size


def _iter_tensor_values(dtype: str, chunk: bytes):
    if dtype == "BF16":
        for (raw,) in struct.iter_unpack("<H", chunk):
            yield _bf16_to_float(raw)
        return

    fmt = _STRUCT_FORMATS[dtype]
    for (raw,) in struct.iter_unpack("<" + fmt, chunk):
        if dtype == "BOOL":
            yield 1.0 if raw else 0.0
        else:
            yield raw


def _bf16_to_float(raw: int) -> float:
    return struct.unpack("<f", struct.pack("<I", raw << 16))[0]


class _StatsAccumulator:
    def __init__(self) -> None:
        self.count = 0
        self.finite_count = 0
        self.nan_count = 0
        self.inf_count = 0
        self.zero_count = 0
        self.min_value: float | None = None
        self.max_value: float | None = None
        self.total = 0.0
        self.sumsq = 0.0

    def add(self, raw: int | float) -> None:
        self.count += 1
        value = float(raw)
        if math.isnan(value):
            self.nan_count += 1
            return
        if math.isinf(value):
            self.inf_count += 1
            return

        self.finite_count += 1
        if value == 0.0:
            self.zero_count += 1
        self.min_value = value if self.min_value is None else min(self.min_value, value)
        self.max_value = value if self.max_value is None else max(self.max_value, value)
        self.total += value
        self.sumsq += value * value

    def finish(self) -> TensorStats:
        mean = self.total / self.finite_count if self.finite_count else None
        l2_norm = math.sqrt(self.sumsq) if self.finite_count else None
        zero_ratio = self.zero_count / self.count if self.count else None
        return TensorStats(
            count=self.count,
            finite_count=self.finite_count,
            nan_count=self.nan_count,
            inf_count=self.inf_count,
            zero_count=self.zero_count,
            min=self.min_value,
            max=self.max_value,
            mean=mean,
            l2_norm=l2_norm,
            zero_ratio=zero_ratio,
        )


def _json_float(value: float | None) -> float | None:
    if value is None:
        return None
    return value if math.isfinite(value) else None


def _err(code: str, message: str) -> SafetensorsParseResult:
    return SafetensorsParseResult(error=message, error_code=code)


def tensor_baseline_for(path: Path) -> dict[str, Any] | None:
    result = inspect_safetensors(path)
    if not result.ok or result.info is None:
        return None
    return result.info.to_baseline()
