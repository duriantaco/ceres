# CI And GitHub Pages

## User AI Security Gate

Use this when a product repository needs CI to block risky AI workflow changes.
The full copyable workflow lives at
`examples/github-actions/ai-security-gate.yml`.

Ceres blocks static AI supply-chain risk in model, dataset, RAG, prompt, eval,
agent-tool, MCP-adjacent, dependency, and CI changes. The workflow fails on
critical, high, or medium findings; low findings are reported in SARIF and JSON
without blocking the build.

```yaml
name: Ceres AI Security Gate
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  static-ai-supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install ceres-scanner pip-audit
      - run: |
          ceres scan . \
            --diff-base origin/${{ github.base_ref || 'main' }} \
            --json-out ceres.json \
            --sarif-out ceres.sarif \
            --fail-on critical,high,medium
      - uses: github/codeql-action/upload-sarif@v3
        if: ${{ always() && hashFiles('ceres.sarif') != '' }}
        with:
          sarif_file: ceres.sarif
```

`--diff-base` is recommended for pull requests because it keeps existing
repository debt out of the review and gates only findings introduced by the
branch. For scheduled or release scans, run `ceres scan .` without diff mode to
review the whole repository.

## Minimal Ceres-Only CI

```yaml
name: Ceres
on: [pull_request, push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .
      - run: ceres scan . --diff-base origin/${{ github.base_ref || 'main' }} --sarif-out ceres.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ceres.sarif
```

## Ceres Repository CI

This repository has its own CI workflow at `.github/workflows/ci.yml`. It runs:

- Ruff lint checks
- unit tests
- strict MkDocs build
- Ceres diff scan on pull requests
- pip-audit availability for Ceres dependency checks
- Skylos scan

## GitHub Pages Docs

This repository includes a Pages workflow at `.github/workflows/docs.yml`.

It builds with:

```bash
python -m mkdocs build --strict --site-dir site
```

Deployment uses GitHub’s first-party Pages actions:

- `actions/upload-pages-artifact`
- `actions/deploy-pages`

In repository settings, set Pages source to **GitHub Actions**. Pushes to
`main` will build and deploy the docs site.

## Local Docs Preview

```bash
python -m pip install mkdocs mkdocs-material
python -m mkdocs serve
```

The generated site uses MkDocs Material, but the Ceres docs have their own nav,
logo, structured data, and teal/green palette.

## Real-World Validation

This repository also includes `.github/workflows/real-world-validation.yml`.
It runs nightly and through `workflow_dispatch`, installs Ceres, runs the
real-world harness unit tests, scans the public corpus in
`examples/real-world-corpus.yml`, and uploads `report.json` as a workflow
artifact.
