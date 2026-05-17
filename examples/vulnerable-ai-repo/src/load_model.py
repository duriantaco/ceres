import pickle
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


API_KEY = "sk-1234567890abcdef1234567890abcdef"  # ceres.prompt.secret_literal


def load():
    # ceres.model.loader.remote_code_enabled + ceres.model.loader.revision_unpinned
    model = AutoModelForCausalLM.from_pretrained(
        "org/some-model",
        trust_remote_code=True,
    )
    tokenizer = AutoTokenizer.from_pretrained("org/some-model")  # unpinned
    return model, tokenizer


def load_pickle():
    # ceres.model.loader.pickle_deserialize
    with open("models/final.pkl", "rb") as f:
        return pickle.load(f)


def load_torch():
    # ceres.model.loader.torch_unsafe_load
    return torch.load("models/checkpoint.pt")


def run_dynamic(code):
    # ceres.ai_code.dynamic_execution
    return eval(code)
