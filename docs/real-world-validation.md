# Real-World Validation

Unit tests prove individual rules. Real-world validation checks whether the
scanner still works inside messy AI repos with normal layouts, existing files,
and unrelated findings.

The harness copies or clones a repo into a temporary workspace, applies known
bad AI supply-chain mutations, runs Ceres, and fails if the expected rule is not
reported on the injected file. By default it uses a combined mutation run, so a
large repo gets one clean scan and one mutated scan instead of one scan per
scenario.

## Run Against A Local Repo

```bash
python scripts/real_world_check.py /path/to/ai-repo \
  --workdir /tmp/ceres-real-world \
  --json-out /tmp/ceres-real-world/report.json
```

## Run Selected Scenarios

```bash
python scripts/real_world_check.py /path/to/ai-repo \
  --scenario hf_trust_remote_code \
  --scenario rag_prompt_injection \
  --scenario agent_shell_tool
```

List available scenarios:

```bash
python scripts/real_world_check.py --list-scenarios
```

To isolate every scenario into its own copied worktree, use:

```bash
python scripts/real_world_check.py /path/to/ai-repo --separate-scenarios
```

## Run Against A Git URL

```bash
python scripts/real_world_check.py https://github.com/example/ai-app.git \
  --workdir /tmp/ceres-real-world \
  --keep-workdir
```

Network access is only needed for Git URLs. Local paths are copied directly.

## Run A Corpus

Use a corpus file when the same repos should run in CI, a nightly job, or a
release gate:

```yaml
repos:
  - source: https://github.com/deepset-ai/haystack.git
  - source: https://github.com/run-llama/llama_index.git
  - source: https://github.com/microsoft/autogen.git

scenarios:
  - hf_trust_remote_code
  - rag_prompt_injection
  - agent_shell_tool
```

Run it with:

```bash
python scripts/real_world_check.py \
  --corpus examples/real-world-corpus.yml \
  --workdir /tmp/ceres-real-world \
  --json-out /tmp/ceres-real-world/report.json
```

Relative local repo paths and a relative `policy:` path are resolved from the
corpus file directory. Command-line `--scenario` and `--policy` values override
the corpus file.

## What It Tests

The current scenarios cover:

- `trust_remote_code=True` plus unpinned Hugging Face revision
- unsafe `torch.load`
- unrestricted shell agent tool
- poisoned tool metadata requesting sensitive context
- visible and hidden RAG prompt injection
- dataset checksum drift
- LoRA base-model drift
- tokenizer chat-template drift
- safetensors tensor hash/norm drift
- unpinned git dependency
- Docker base image not pinned by digest

## CI Use

Use this as a nightly or pre-release job against a curated repo corpus. Keep
normal PR CI fast with unit tests and one small example scan.

The combined-mode console output prints the expected rules that matched for
each scenario. The JSON report also keeps the full injected finding list for
triage.

Set clean-scan budgets in `ceres.yml` to make the corpus fail on noise or
analyzer failures:

```yaml
real_world_validation:
  clean_budgets:
    critical: 0
    high: 20
    analyzer_failures: 0
```

```yaml
name: Ceres real-world validation
on:
  workflow_dispatch:
  schedule:
    - cron: "0 5 * * *"

jobs:
  real-world:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .
      - run: |
          python scripts/real_world_check.py \
            --corpus examples/real-world-corpus.yml \
            --workdir /tmp/ceres-real-world \
            --json-out /tmp/ceres-real-world/report.json
```

For private corpora, mount or checkout the repos before running the harness.
