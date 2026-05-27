from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO


DEFAULT_MAX_STRING_BYTES = 1024 * 1024
DEFAULT_MAX_METADATA_ENTRIES = 4096
DEFAULT_MAX_NODES = 200_000
DEFAULT_MAX_OP_TYPES = 4096

_WT_VARINT = 0
_WT_FIXED64 = 1
_WT_LENGTH_DELIMITED = 2
_WT_FIXED32 = 5


@dataclass(frozen=True)
class ONNXInfo:
    ir_version: int | None
    producer_name: str | None
    producer_version: str | None
    domain: str | None
    model_version: int | None
    graph_name: str | None
    opset_imports: dict[str, int]
    metadata_props: dict[str, str]
    node_op_counts: dict[str, int]
    node_count: int
    metadata_sha256: str
    operator_sha256: str

    def to_baseline(self) -> dict[str, Any]:
        return {
            "format": "onnx",
            "ir_version": self.ir_version,
            "producer_name": self.producer_name,
            "producer_version": self.producer_version,
            "domain": self.domain,
            "model_version": self.model_version,
            "graph_name": self.graph_name,
            "opset_imports": self.opset_imports,
            "metadata_props": self.metadata_props,
            "node_op_counts": self.node_op_counts,
            "node_count": self.node_count,
            "metadata_sha256": self.metadata_sha256,
            "operator_sha256": self.operator_sha256,
        }


@dataclass(frozen=True)
class ONNXParseResult:
    info: ONNXInfo | None = None
    error: str | None = None
    error_code: str | None = None

    @property
    def ok(self) -> bool:
        return self.info is not None and self.error is None


class _ONNXError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _Reader:
    def __init__(self, f: BinaryIO, *, end: int, max_string_bytes: int) -> None:
        self.f = f
        self.end = end
        self.max_string_bytes = max_string_bytes

    def pos(self) -> int:
        return self.f.tell()

    def eof(self) -> bool:
        return self.pos() >= self.end

    def read_exact(self, n: int) -> bytes:
        if n < 0 or self.pos() + n > self.end:
            raise _ONNXError("ceres.model.onnx.header_invalid", "ONNX protobuf is truncated.")
        data = self.f.read(n)
        if len(data) != n:
            raise _ONNXError("ceres.model.onnx.header_invalid", "ONNX protobuf is truncated.")
        return data

    def read_varint(self) -> int:
        shift = 0
        value = 0
        for _ in range(10):
            raw = self.read_exact(1)[0]
            value |= (raw & 0x7F) << shift
            if not raw & 0x80:
                return value
            shift += 7
        raise _ONNXError("ceres.model.onnx.header_invalid", "ONNX protobuf varint is too long.")

    def read_tag(self) -> tuple[int, int] | None:
        if self.eof():
            return None
        tag = self.read_varint()
        field = tag >> 3
        wire_type = tag & 0x07
        if field == 0:
            raise _ONNXError("ceres.model.onnx.header_invalid", "ONNX protobuf has invalid field number 0.")
        return field, wire_type

    def read_string(self) -> str | None:
        size = self.read_varint()
        if size > self.max_string_bytes:
            raise _ONNXError(
                "ceres.model.onnx.metadata_oversized",
                f"ONNX string metadata entry is {size} bytes, above configured limit {self.max_string_bytes}.",
            )
        raw = self.read_exact(size)
        return raw.decode("utf-8", errors="replace")

    def subreader(self) -> "_Reader":
        size = self.read_varint()
        end = self.pos() + size
        if end > self.end:
            raise _ONNXError("ceres.model.onnx.header_invalid", "ONNX protobuf message is truncated.")
        return _Reader(self.f, end=end, max_string_bytes=self.max_string_bytes)

    def finish_subreader(self, sub: "_Reader") -> None:
        if self.f.tell() < sub.end:
            self.f.seek(sub.end)

    def skip_value(self, wire_type: int) -> None:
        if wire_type == _WT_VARINT:
            self.read_varint()
        elif wire_type == _WT_FIXED64:
            self.skip_bytes(8)
        elif wire_type == _WT_LENGTH_DELIMITED:
            self.skip_bytes(self.read_varint())
        elif wire_type == _WT_FIXED32:
            self.skip_bytes(4)
        else:
            raise _ONNXError("ceres.model.onnx.header_invalid", f"Unsupported ONNX protobuf wire type {wire_type}.")

    def skip_bytes(self, n: int) -> None:
        if n < 0 or self.pos() + n > self.end:
            raise _ONNXError("ceres.model.onnx.header_invalid", "ONNX protobuf is truncated.")
        self.f.seek(n, 1)


def inspect_onnx(
    path: Path,
    *,
    max_string_bytes: int = DEFAULT_MAX_STRING_BYTES,
    max_metadata_entries: int = DEFAULT_MAX_METADATA_ENTRIES,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_op_types: int = DEFAULT_MAX_OP_TYPES,
) -> ONNXParseResult:
    try:
        file_size = path.stat().st_size
        if file_size == 0:
            return _err("ceres.model.onnx.header_invalid", "ONNX file is empty.")
        with path.open("rb") as f:
            reader = _Reader(f, end=file_size, max_string_bytes=max_string_bytes)
            state = _ModelState(max_metadata_entries=max_metadata_entries)
            while not reader.eof():
                tag = reader.read_tag()
                if tag is None:
                    break
                field, wire_type = tag
                if field == 1 and wire_type == _WT_VARINT:
                    state.ir_version = reader.read_varint()
                elif field == 2 and wire_type == _WT_LENGTH_DELIMITED:
                    state.producer_name = reader.read_string()
                elif field == 3 and wire_type == _WT_LENGTH_DELIMITED:
                    state.producer_version = reader.read_string()
                elif field == 4 and wire_type == _WT_LENGTH_DELIMITED:
                    state.domain = reader.read_string()
                elif field == 5 and wire_type == _WT_VARINT:
                    state.model_version = reader.read_varint()
                elif field == 7 and wire_type == _WT_LENGTH_DELIMITED:
                    sub = reader.subreader()
                    _parse_graph(sub, state, max_nodes=max_nodes, max_op_types=max_op_types)
                    reader.finish_subreader(sub)
                elif field == 8 and wire_type == _WT_LENGTH_DELIMITED:
                    sub = reader.subreader()
                    domain, version = _parse_opset(sub)
                    reader.finish_subreader(sub)
                    if version is not None:
                        state.opset_imports[domain or ""] = version
                elif field == 14 and wire_type == _WT_LENGTH_DELIMITED:
                    sub = reader.subreader()
                    key, value = _parse_metadata_prop(sub)
                    reader.finish_subreader(sub)
                    if key:
                        state.add_metadata(key, value or "")
                else:
                    reader.skip_value(wire_type)

            info = state.to_info()
            if not _looks_like_onnx(info):
                return _err("ceres.model.onnx.header_invalid", "ONNX protobuf did not contain recognizable model metadata.")
            return ONNXParseResult(info=info)
    except OSError as e:
        return _err("ceres.model.onnx.header_invalid", f"Unable to read ONNX file: {e}.")
    except _ONNXError as e:
        return _err(e.code, e.message)
    except UnicodeError as e:
        return _err("ceres.model.onnx.header_invalid", f"ONNX metadata could not be parsed: {e}.")


def onnx_baseline_for(path: Path) -> dict[str, Any] | None:
    result = inspect_onnx(path)
    if result.ok and result.info is not None:
        return result.info.to_baseline()
    return None


class _ModelState:
    def __init__(self, *, max_metadata_entries: int) -> None:
        self.ir_version: int | None = None
        self.producer_name: str | None = None
        self.producer_version: str | None = None
        self.domain: str | None = None
        self.model_version: int | None = None
        self.graph_name: str | None = None
        self.opset_imports: dict[str, int] = {}
        self.metadata_props: dict[str, str] = {}
        self.node_op_counts: dict[str, int] = {}
        self.node_count = 0
        self.max_metadata_entries = max_metadata_entries

    def add_metadata(self, key: str, value: str) -> None:
        if len(self.metadata_props) >= self.max_metadata_entries and key not in self.metadata_props:
            raise _ONNXError(
                "ceres.model.onnx.metadata_oversized",
                f"ONNX metadata property count exceeds limit {self.max_metadata_entries}.",
            )
        self.metadata_props[key] = value

    def add_node(self, domain: str | None, op_type: str | None, *, max_op_types: int) -> None:
        self.node_count += 1
        if not op_type:
            return
        op = f"{domain}::{op_type}" if domain else op_type
        if op not in self.node_op_counts and len(self.node_op_counts) >= max_op_types:
            raise _ONNXError(
                "ceres.model.onnx.metadata_oversized",
                f"ONNX operator type count exceeds limit {max_op_types}.",
            )
        self.node_op_counts[op] = self.node_op_counts.get(op, 0) + 1

    def to_info(self) -> ONNXInfo:
        metadata_identity = {
            "ir_version": self.ir_version,
            "producer_name": self.producer_name,
            "producer_version": self.producer_version,
            "domain": self.domain,
            "model_version": self.model_version,
            "graph_name": self.graph_name,
            "metadata_props": self.metadata_props,
        }
        return ONNXInfo(
            ir_version=self.ir_version,
            producer_name=self.producer_name,
            producer_version=self.producer_version,
            domain=self.domain,
            model_version=self.model_version,
            graph_name=self.graph_name,
            opset_imports=dict(sorted(self.opset_imports.items())),
            metadata_props=dict(sorted(self.metadata_props.items())),
            node_op_counts=dict(sorted(self.node_op_counts.items())),
            node_count=self.node_count,
            metadata_sha256=_stable_digest(metadata_identity),
            operator_sha256=_stable_digest(
                {"node_count": self.node_count, "node_op_counts": self.node_op_counts}
            ),
        )


def _parse_graph(
    reader: _Reader,
    state: _ModelState,
    *,
    max_nodes: int,
    max_op_types: int,
) -> None:
    while not reader.eof():
        tag = reader.read_tag()
        if tag is None:
            break
        field, wire_type = tag
        if field == 1 and wire_type == _WT_LENGTH_DELIMITED:
            if state.node_count >= max_nodes:
                raise _ONNXError(
                    "ceres.model.onnx.metadata_oversized",
                    f"ONNX graph node count exceeds limit {max_nodes}.",
                )
            sub = reader.subreader()
            domain, op_type = _parse_node(sub)
            reader.finish_subreader(sub)
            state.add_node(domain, op_type, max_op_types=max_op_types)
        elif field == 2 and wire_type == _WT_LENGTH_DELIMITED:
            state.graph_name = reader.read_string()
        else:
            reader.skip_value(wire_type)


def _parse_node(reader: _Reader) -> tuple[str | None, str | None]:
    domain = None
    op_type = None
    while not reader.eof():
        tag = reader.read_tag()
        if tag is None:
            break
        field, wire_type = tag
        if field == 4 and wire_type == _WT_LENGTH_DELIMITED:
            op_type = reader.read_string()
        elif field == 7 and wire_type == _WT_LENGTH_DELIMITED:
            domain = reader.read_string()
        else:
            reader.skip_value(wire_type)
    return domain, op_type


def _parse_opset(reader: _Reader) -> tuple[str | None, int | None]:
    domain = None
    version = None
    while not reader.eof():
        tag = reader.read_tag()
        if tag is None:
            break
        field, wire_type = tag
        if field == 1 and wire_type == _WT_LENGTH_DELIMITED:
            domain = reader.read_string()
        elif field == 2 and wire_type == _WT_VARINT:
            version = reader.read_varint()
        else:
            reader.skip_value(wire_type)
    return domain, version


def _parse_metadata_prop(reader: _Reader) -> tuple[str | None, str | None]:
    key = None
    value = None
    while not reader.eof():
        tag = reader.read_tag()
        if tag is None:
            break
        field, wire_type = tag
        if field == 1 and wire_type == _WT_LENGTH_DELIMITED:
            key = reader.read_string()
        elif field == 2 and wire_type == _WT_LENGTH_DELIMITED:
            value = reader.read_string()
        else:
            reader.skip_value(wire_type)
    return key, value


def _looks_like_onnx(info: ONNXInfo) -> bool:
    # ONNX ModelProto requires at least one opset_import. Without it, a truncated
    # prefix with only incidental metadata can look parseable but is not a usable model.
    return info.ir_version is not None and bool(info.opset_imports)


def _stable_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _err(code: str, message: str) -> ONNXParseResult:
    return ONNXParseResult(error=message, error_code=code)
