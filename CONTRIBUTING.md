# Contributing to KubeRoast

Thanks for your interest in making KubeRoast better. This document covers how to set up a dev environment, the testing/linting expectations, and how to add new security checks.

## Development setup

```bash
git clone https://github.com/SnailSploit/KubeRoast_v1.git
cd KubeRoast_v1
make dev
```

Or manually:

```bash
python -m pip install -e ".[dev]"
```

## Running tests

```bash
make test           # quick run
make coverage       # with coverage report
```

KubeRoast targets Python 3.9 through 3.12. CI runs the full matrix on every PR.

## Linting & formatting

We use [ruff](https://github.com/astral-sh/ruff) for both lint and format:

```bash
make lint           # check
make format         # auto-fix
```

Ruff config lives in `pyproject.toml` under `[tool.ruff]`.

## Adding a new check

1. Decide which scanner module fits (`kuberoast/scanners/*.py`) or create a new one.
2. Add a `Finding` with a stable, namespaced ID like `POD-NEW-CHECK`.
3. Map the new ID to its CIS Kubernetes Benchmark control(s), MITRE ATT&CK technique(s), and CWE(s) in `kuberoast/utils/compliance.py`. Findings without a mapping still work, just without enrichment.
4. Add unit tests in `tests/` exercising both positive and negative cases.
5. Update the README finding tables.

### Finding guidelines

- **Severity** — Ground severity in public guidance (CIS, NIST, vendor docs) or reproducible attacker tradecraft. Don't inflate. Defaults: privilege escalation = critical, data exposure = high, hardening gap = medium/low.
- **Description** — One sentence stating *what* is wrong and *why* it matters.
- **Remediation** — Imperative, copy-pasteable next step. Include the K8s field/manifest snippet when possible.
- **References** — Prefer canonical Kubernetes docs, CIS, NIST, or peer-reviewed write-ups. Avoid vendor blogs unless they are the authoritative source.

## Pull request checklist

- [ ] `make test` passes locally
- [ ] `make lint` is clean
- [ ] New checks have unit tests for both detection and non-detection
- [ ] New finding IDs are mapped in `compliance.py`
- [ ] README finding tables updated if applicable
- [ ] CHANGELOG entry added under `## [Unreleased]`

## Reporting security issues

See [SECURITY.md](./SECURITY.md). Please do not open public issues for vulnerabilities.
