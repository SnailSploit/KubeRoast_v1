# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-05-08

### Added
- **Compliance enrichment** — every finding is automatically tagged with CIS
  Kubernetes Benchmark controls, MITRE ATT&CK techniques, and CWE IDs.
- **SARIF v2.1.0 output** (`--report sarif`) for GitHub code scanning, Azure
  DevOps, and other static-analysis dashboards.
- **JUnit XML output** (`--report junit`) for Jenkins / GitLab / CircleCI.
- **CSV output** (`--report csv`) for spreadsheets and analytics.
- **Offline manifest scanning** (`--manifests <dir|file>`) — scan YAML/JSON
  manifests without a live cluster. Supports Pod, Deployment, StatefulSet,
  DaemonSet, Job, CronJob, ReplicaSet, ReplicationController, RBAC, Secret,
  Service, Ingress, Namespace, and CRD kinds.
- **Dockerfile** — non-root, multi-stage container image for portable scans.
- **GitHub Actions CI** — test matrix (Python 3.9–3.12), ruff lint, build, and
  Docker image build.
- **GitHub Actions security-scan workflow** — example pipeline that uploads
  SARIF results to GitHub code scanning.
- **Makefile** with `install`, `dev`, `test`, `coverage`, `lint`, `format`,
  `build`, `docker`, `clean` targets.
- **`--version` flag**, `-q/--quiet` flag, ISO-8601 structured log timestamps,
  and `--no-compliance` opt-out.
- Richer HTML report with severity stat cards and CIS/MITRE/CWE chips.
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, and GitHub issue/PR
  templates.

### Changed
- Bumped package version from 0.2.0 to 0.3.0.
- Text reporter now displays the finding ID, namespace, and compliance
  metadata when present.
- HTML reporter redesigned with a summary-stats header and tag chips.

### Notes
This release is backwards-compatible at the CLI level: existing
`--report {json,text,html}` flows continue to work.

## [0.2.0]

Initial public release with 30+ checks across Pod Security, RBAC, Network,
Node, Secrets, Policy, and PSS categories.
