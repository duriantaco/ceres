from __future__ import annotations


def load_weights(path: str):
    from safetensors.torch import load_file
    return load_file(path)
