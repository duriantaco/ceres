from __future__ import annotations

import pickletools
import zipfile
import pickle
from dataclasses import dataclass
from pathlib import Path

_MAX_BYTES = 64 * 1024 * 1024
_MAX_OPS = 200_000

_SUSPICIOUS_GLOBALS = {
    "os.system",
    "subprocess.",
    "pty.",
    "posix.",
    "nt.",
    "shutil.",
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "builtins.__import__",
    "builtins.getattr",
    "builtins.setattr",
    "operator.attrgetter",
    "operator.methodcaller",
    "code.InteractiveInterpreter",
    "importlib.",
    "ctypes.",
    "socket.",
    "requests.",
    "urllib.",
    "http.client.",
    "pickle.loads",
    "marshal.loads",
    "base64.b64decode",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.check_output",
}
_SUSPICIOUS_PREFIXES = {item for item in _SUSPICIOUS_GLOBALS if item.endswith(".")}
_SUSPICIOUS_EXACT = _SUSPICIOUS_GLOBALS - _SUSPICIOUS_PREFIXES


@dataclass
class PickleScanResult:
    suspicious_globals: list[str]
    has_reduce: bool
    opcode_count: int
    truncated: bool
    error: str | None = None

    @property
    def is_dangerous(self) -> bool:
        return bool(self.suspicious_globals)


def scan_pickle_bytes(data: bytes) -> PickleScanResult:
    suspicious: list[str] = []
    has_reduce = False
    count = 0
    truncated = False
    try:
        for op, arg, _pos in pickletools.genops(data[:_MAX_BYTES]):
            count += 1
            if count > _MAX_OPS:
                truncated = True
                break
            name = op.name
            if name == "REDUCE":
                has_reduce = True
            if name in {"GLOBAL", "STACK_GLOBAL"}:
                if name == "STACK_GLOBAL":
                    suspicious.append("STACK_GLOBAL (dynamic global resolution)")
                    continue
                ref = arg if isinstance(arg, str) else " ".join(arg) if arg else ""
                ref_norm = ref.replace(" ", ".")
                if _matches_any(ref_norm, _SUSPICIOUS_GLOBALS):
                    suspicious.append(ref_norm)
            if name in {"INST", "OBJ"}:
                if isinstance(arg, str) and _matches_any(arg.replace(" ", "."), _SUSPICIOUS_GLOBALS):
                    suspicious.append(arg)
    except Exception as e:  # noqa: BLE001
        return PickleScanResult(suspicious, has_reduce, count, truncated, error=str(e))
    return PickleScanResult(suspicious, has_reduce, count, truncated)


def _matches_any(ref: str, fragments: set[str]) -> bool:
    if ref in _SUSPICIOUS_EXACT:
        return True
    return any(ref.startswith(prefix) for prefix in _SUSPICIOUS_PREFIXES)


def scan_path(path: Path) -> PickleScanResult | None:
    suffix = path.suffix.lower()
    try:
        if suffix in {".pkl", ".pickle", ".joblib"}:
            with path.open("rb") as f:
                return scan_pickle_bytes(f.read(_MAX_BYTES))
        if suffix in {".pt", ".pth", ".bin", ".ckpt"}:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as zf:
                    for name in zf.namelist():
                        if name.endswith("data.pkl") or name.endswith(".pkl"):
                            with zf.open(name) as inner:
                                return scan_pickle_bytes(inner.read(_MAX_BYTES))
                return None
            with path.open("rb") as f:
                data = f.read(_MAX_BYTES)
            if not _looks_like_pickle(data):
                return None
            return scan_pickle_bytes(data)
    except (OSError, zipfile.BadZipFile) as e:
        return PickleScanResult([], False, 0, False, error=str(e))
    return None


def _looks_like_pickle(data: bytes) -> bool:
    if len(data) >= 2 and data[0] == 0x80 and data[1] <= pickle.HIGHEST_PROTOCOL:
        return True
    return data[:1] in {b"c", b"(", b"]", b"}", b"l", b"d", b"I", b"F", b"S", b"V"}
