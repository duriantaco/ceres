from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO


DEFAULT_MAX_METADATA_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_STRING_BYTES = 1024 * 1024
DEFAULT_MAX_METADATA_ENTRIES = 16_384
DEFAULT_MAX_ARRAY_ELEMENTS = 1_000_000
DEFAULT_MAX_TENSORS = 1_000_000
DEFAULT_MAX_DIMS = 16

_VALUE_TYPES = {
    0: "UINT8",
    1: "INT8",
    2: "UINT16",
    3: "INT16",
    4: "UINT32",
    5: "INT32",
    6: "FLOAT32",
    7: "BOOL",
    8: "STRING",
    9: "ARRAY",
    10: "UINT64",
    11: "INT64",
    12: "FLOAT64",
}

_PRIMITIVE_FORMATS = {
    0: "<B",
    1: "<b",
    2: "<H",
    3: "<h",
    4: "<I",
    5: "<i",
    6: "<f",
    7: "<?",
    10: "<Q",
    11: "<q",
    12: "<d",
}

_TENSOR_TYPES = {
    0: "F32",
    1: "F16",
    2: "Q4_0",
    3: "Q4_1",
    6: "Q5_0",
    7: "Q5_1",
    8: "Q8_0",
    9: "Q8_1",
    10: "Q2_K",
    11: "Q3_K",
    12: "Q4_K",
    13: "Q5_K",
    14: "Q6_K",
    15: "Q8_K",
    16: "IQ2_XXS",
    17: "IQ2_XS",
    18: "IQ3_XXS",
    19: "IQ1_S",
    20: "IQ4_NL",
    21: "IQ3_S",
    22: "IQ2_S",
    23: "IQ4_XS",
    24: "I8",
    25: "I16",
    26: "I32",
    27: "I64",
    28: "F64",
    29: "IQ1_M",
    30: "BF16",
    31: "Q4_0_4_4",
    32: "Q4_0_4_8",
    33: "Q4_0_8_8",
    34: "TQ1_0",
    35: "TQ2_0",
}


@dataclass(frozen=True)
class GGUFTensorInfo:
    name: str
    shape: tuple[int, ...]
    tensor_type: str
    offset: int

    def to_baseline(self) -> dict[str, Any]:
        return {
            "shape": list(self.shape),
            "type": self.tensor_type,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class GGUFInfo:
    version: int
    metadata: dict[str, Any]
    tensors: dict[str, GGUFTensorInfo]
    metadata_kv_count: int
    tensor_count: int
    header_bytes: int
    metadata_sha256: str
    tensor_names_sha256: str

    def to_baseline(self) -> dict[str, Any]:
        return {
            "format": "gguf",
            "version": self.version,
            "metadata_kv_count": self.metadata_kv_count,
            "tensor_count": self.tensor_count,
            "header_bytes": self.header_bytes,
            "metadata": self.metadata,
            "metadata_sha256": self.metadata_sha256,
            "tensor_names_sha256": self.tensor_names_sha256,
            "tensors": {name: tensor.to_baseline() for name, tensor in self.tensors.items()},
        }


@dataclass(frozen=True)
class GGUFParseResult:
    info: GGUFInfo | None = None
    error: str | None = None
    error_code: str | None = None

    @property
    def ok(self) -> bool:
        return self.info is not None and self.error is None


class _GGUFError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _Reader:
    def __init__(
        self,
        f: BinaryIO,
        *,
        file_size: int,
        metadata_start: int,
        max_metadata_bytes: int,
        max_string_bytes: int,
        max_array_elements: int,
    ) -> None:
        self.f = f
        self.file_size = file_size
        self.metadata_start = metadata_start
        self.max_metadata_bytes = max_metadata_bytes
        self.max_string_bytes = max_string_bytes
        self.max_array_elements = max_array_elements

    def pos(self) -> int:
        return self.f.tell()

    def check_metadata_limit(self) -> None:
        used = self.pos() - self.metadata_start
        if used > self.max_metadata_bytes:
            raise _GGUFError(
                "ceres.model.gguf.metadata_oversized",
                f"GGUF metadata is above configured limit {self.max_metadata_bytes} bytes.",
            )

    def read_exact(self, n: int) -> bytes:
        if n < 0:
            raise _GGUFError("ceres.model.gguf.header_invalid", "GGUF parser received a negative read length.")
        if self.pos() + n > self.file_size:
            raise _GGUFError("ceres.model.gguf.header_invalid", "GGUF file is truncated.")
        data = self.f.read(n)
        if len(data) != n:
            raise _GGUFError("ceres.model.gguf.header_invalid", "GGUF file is truncated.")
        self.check_metadata_limit()
        return data

    def read_u32(self) -> int:
        return struct.unpack("<I", self.read_exact(4))[0]

    def read_u64(self) -> int:
        return struct.unpack("<Q", self.read_exact(8))[0]

    def read_string(self) -> str:
        size = self.read_u64()
        if size > self.max_string_bytes:
            raise _GGUFError(
                "ceres.model.gguf.metadata_oversized",
                f"GGUF string metadata entry is {size} bytes, above configured limit {self.max_string_bytes}.",
            )
        raw = self.read_exact(size)
        return raw.decode("utf-8", errors="replace")

    def skip(self, n: int) -> bytes:
        return self.read_exact(n)


def inspect_gguf(
    path: Path,
    *,
    max_metadata_bytes: int = DEFAULT_MAX_METADATA_BYTES,
    max_string_bytes: int = DEFAULT_MAX_STRING_BYTES,
    max_metadata_entries: int = DEFAULT_MAX_METADATA_ENTRIES,
    max_array_elements: int = DEFAULT_MAX_ARRAY_ELEMENTS,
    max_tensors: int = DEFAULT_MAX_TENSORS,
    max_dims: int = DEFAULT_MAX_DIMS,
) -> GGUFParseResult:
    try:
        file_size = path.stat().st_size
        with path.open("rb") as f:
            prefix = f.read(24)
            if len(prefix) < 24:
                return _err("ceres.model.gguf.header_invalid", "GGUF file is smaller than the fixed header.")
            if prefix[:4] != b"GGUF":
                return _err("ceres.model.gguf.header_invalid", "GGUF magic header is missing.")
            version, tensor_count, metadata_kv_count = struct.unpack("<IQQ", prefix[4:24])
            if version not in {2, 3}:
                return _err("ceres.model.gguf.header_invalid", f"Unsupported GGUF version {version}.")
            if metadata_kv_count > max_metadata_entries:
                return _err(
                    "ceres.model.gguf.metadata_oversized",
                    f"GGUF metadata entry count {metadata_kv_count} exceeds limit {max_metadata_entries}.",
                )
            if tensor_count > max_tensors:
                return _err(
                    "ceres.model.gguf.metadata_oversized",
                    f"GGUF tensor count {tensor_count} exceeds limit {max_tensors}.",
                )

            reader = _Reader(
                f,
                file_size=file_size,
                metadata_start=24,
                max_metadata_bytes=max_metadata_bytes,
                max_string_bytes=max_string_bytes,
                max_array_elements=max_array_elements,
            )
            metadata: dict[str, Any] = {}
            for _ in range(metadata_kv_count):
                key = reader.read_string()
                value_type = reader.read_u32()
                metadata[key] = _read_value(reader, value_type)

            tensors: dict[str, GGUFTensorInfo] = {}
            for _ in range(tensor_count):
                name = reader.read_string()
                n_dims = reader.read_u32()
                if n_dims > max_dims:
                    return _err(
                        "ceres.model.gguf.header_invalid",
                        f"GGUF tensor '{name}' has {n_dims} dimensions, above limit {max_dims}.",
                    )
                shape = tuple(reader.read_u64() for _ in range(n_dims))
                raw_type = reader.read_u32()
                offset = reader.read_u64()
                tensors[name] = GGUFTensorInfo(
                    name=name,
                    shape=shape,
                    tensor_type=_TENSOR_TYPES.get(raw_type, f"TYPE_{raw_type}"),
                    offset=offset,
                )

            info = GGUFInfo(
                version=version,
                metadata=metadata,
                tensors=tensors,
                metadata_kv_count=metadata_kv_count,
                tensor_count=tensor_count,
                header_bytes=reader.pos(),
                metadata_sha256=_stable_digest(metadata),
                tensor_names_sha256=_stable_digest(sorted(tensors)),
            )
            return GGUFParseResult(info=info)
    except OSError as e:
        return _err("ceres.model.gguf.header_invalid", f"Unable to read GGUF file: {e}.")
    except _GGUFError as e:
        return _err(e.code, e.message)
    except (struct.error, UnicodeError) as e:
        return _err("ceres.model.gguf.header_invalid", f"GGUF metadata could not be parsed: {e}.")


def gguf_baseline_for(path: Path) -> dict[str, Any] | None:
    result = inspect_gguf(path)
    if result.ok and result.info is not None:
        return result.info.to_baseline()
    return None


def _read_value(reader: _Reader, value_type: int) -> Any:
    if value_type in _PRIMITIVE_FORMATS:
        fmt = _PRIMITIVE_FORMATS[value_type]
        return struct.unpack(fmt, reader.read_exact(struct.calcsize(fmt)))[0]
    if value_type == 8:
        return reader.read_string()
    if value_type == 9:
        return _read_array(reader)
    raise _GGUFError("ceres.model.gguf.header_invalid", f"Unknown GGUF metadata value type {value_type}.")


def _read_array(reader: _Reader) -> dict[str, Any]:
    subtype = reader.read_u32()
    length = reader.read_u64()
    if length > reader.max_array_elements:
        raise _GGUFError(
            "ceres.model.gguf.metadata_oversized",
            f"GGUF metadata array has {length} entries, above configured limit {reader.max_array_elements}.",
        )
    digest = hashlib.sha256()
    sample: list[Any] = []
    for index in range(length):
        value, raw = _read_array_item(reader, subtype)
        digest.update(raw)
        if index < 5:
            sample.append(value)
    return {
        "type": "array",
        "item_type": _VALUE_TYPES.get(subtype, f"TYPE_{subtype}"),
        "length": length,
        "sha256": digest.hexdigest(),
        "sample": sample,
    }


def _read_array_item(reader: _Reader, value_type: int) -> tuple[Any, bytes]:
    if value_type in _PRIMITIVE_FORMATS:
        fmt = _PRIMITIVE_FORMATS[value_type]
        raw = reader.read_exact(struct.calcsize(fmt))
        return struct.unpack(fmt, raw)[0], raw
    if value_type == 8:
        size_raw = reader.read_exact(8)
        size = struct.unpack("<Q", size_raw)[0]
        if size > reader.max_string_bytes:
            raise _GGUFError(
                "ceres.model.gguf.metadata_oversized",
                f"GGUF string array item is {size} bytes, above configured limit {reader.max_string_bytes}.",
            )
        raw = reader.read_exact(size)
        return raw.decode("utf-8", errors="replace"), size_raw + raw
    raise _GGUFError("ceres.model.gguf.header_invalid", f"Unsupported GGUF array item type {value_type}.")


def _stable_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _err(code: str, message: str) -> GGUFParseResult:
    return GGUFParseResult(error=message, error_code=code)
