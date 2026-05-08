<div align="center">

```
 ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗  █████╗ ███████╗████████╗
 ██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝
 █████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝██║   ██║███████║███████╗   ██║
 ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗██║   ██║██╔══██║╚════██║   ██║
 ██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║╚██████╔╝██║  ██║███████║   ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝
```

**Offensive Kubernetes misconfig & attack-path scanner.**
Fast · opinionated · read-only · built for real-world escalation paths.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](#)
[![License MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](./LICENSE)
[![Version 0.3.0](https://img.shields.io/badge/version-0.3.0-orange?style=for-the-badge)](./CHANGELOG.md)
[![Tests 146](https://img.shields.io/badge/tests-146%20passing-brightgreen?style=for-the-badge)](#)

[![SARIF v2.1.0](https://img.shields.io/badge/output-SARIF%20v2.1.0-blueviolet?style=flat-square)](#sarif)
[![CIS Kubernetes](https://img.shields.io/badge/maps_to-CIS%20Kubernetes-informational?style=flat-square)](#compliance-mappings)
[![MITRE ATT&CK](https://img.shields.io/badge/maps_to-MITRE%20ATT%26CK-red?style=flat-square)](#compliance-mappings)
[![CWE](https://img.shields.io/badge/maps_to-CWE-yellow?style=flat-square)](#compliance-mappings)

[Quick Start](#quick-start) ·
[What It Finds](#what-it-finds) ·
[Usage](#usage) ·
[CI/CD](#cicd-integration) ·
[Output](#output-formats) ·
[Contributing](#contributing)

</div>

---

> ⚠️ **Ethical use only.** Run KubeRoast only on clusters you own or have explicit written permission to test.

## Why KubeRoast

Most Kubernetes security scanners generate noise. KubeRoast focuses on **what actually gets you owned** — privilege escalation paths, exposed kubelets, over-permissioned RBAC, network services open to the internet, and secrets sitting in plain sight. It reads, never writes. Safe to run in production.

Every finding is automatically mapped to the **CIS Kubernetes Benchmark**, **MITRE ATT&CK for Containers**, and **CWE**, and reports can be emitted as **SARIF v2.1.0** for direct upload to GitHub code scanning, **JUnit XML** for CI test dashboards, **CSV** for analytics, plus the original JSON / text / HTML formats. KubeRoast also runs **offline against YAML/JSON manifests** so you can shift-left in PR pipelines.

### What it looks like

```text
 ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗  █████╗ ███████╗████████╗
 ██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝
 █████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝██║   ██║███████║███████╗   ██║
 ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗██║   ██║██╔══██║╚════██║   ██║
 ██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║╚██████╔╝██║  ██║███████║   ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝
 v0.3.0  •  Offensive Kubernetes misconfig & attack-path scanner

KubeRoast scan results
────────────────────────────────────────────────────────────────────────
Found 17 issues — 4 critical · 8 high · 5 medium

✖ CRITICAL (4)
──────────────
  [CRITICAL] Privileged container (POD-PRIV)
    Resource    pod/insecure-demo::app
    Namespace   default
    Description Container runs in privileged mode, granting broad access to the host kernel.
    Remediation Remove privileged=true. Grant narrow capabilities only if needed.
    CIS         CIS-K8s-5.2.1, CIS-K8s-5.2.2
    MITRE       T1611, T1610
    CWE         CWE-250, CWE-269
```

## Quick Start

```bash
# Install
git clone https://github.com/SnailSploit/KubeRoast_v1.git
cd KubeRoast_v1
pip install -e .

# Scan your live cluster
kuberoast --report text

# Or scan a directory of manifests (no cluster required)
kuberoast --manifests ./k8s --report text
```

That's it. Live scans use your current kubeconfig context automatically.

### Container

```bash
docker build -t kuberoast .
# Scan manifests mounted at /workspace
docker run --rm -v "$(pwd):/workspace:ro" kuberoast --manifests /workspace --report text
# Scan a cluster using your local kubeconfig
docker run --rm -v "$HOME/.kube:/home/kuberoast/.kube:ro" kuberoast --report text
```

## What It Finds

KubeRoast runs **30+ security checks** across 7 categories. Every finding includes severity, a description, actionable remediation, and reference links.

### Pod Security (11 checks)

| ID | Finding | Severity |
|---|---|---|
| `POD-PRIV` | Privileged container | Critical |
| `POD-ROOT` | Container runs as root (`runAsUser=0`) | High |
| `POD-PE` | `allowPrivilegeEscalation` not disabled | High/Medium |
| `POD-HOSTNS` | Pod uses host namespaces (network/PID/IPC) | High |
| `POD-CAPS` | Dangerous Linux capabilities (`SYS_ADMIN`, `SYS_PTRACE`, etc.) | High |
| `POD-HOSTPATH` | hostPath volume mounted | High |
| `POD-RWFS` | Writable root filesystem | Medium |
| `POD-NO-SECCOMP` | No seccomp profile configured | Medium |
| `POD-NO-LIMITS` | No CPU/memory resource limits | Medium |
| `POD-SATOKEN` | Service account token automount not disabled | Low |
| `POD-NO-APPARMOR` | No AppArmor profile configured | Low |

### RBAC (5 checks)

| ID | Finding | Severity |
|---|---|---|
| `RBAC-ANON` | Anonymous or wildcard user bound | Critical |
| `RBAC-CLUSTER-ADMIN` | `cluster-admin` granted via binding | Critical |
| `RBAC-ESCALATION-VERB` | Escalation verbs (`bind`/`escalate`/`impersonate`) | Critical |
| `RBAC-WILDCARD` | Wildcard `*` in role rules | High |
| `RBAC-SENSITIVE-WRITE` | Write access to sensitive resources | High |

### Attack Path Modeling (1 composite check)

| ID | Finding | Severity |
|---|---|---|
| `AP-RBAC-ESC` | RBAC permissions enable privilege escalation | Critical |

Maps every principal (especially ServiceAccounts) to concrete escalation abilities — bind, escalate, impersonate, create pods + read secrets, exec/attach, modify nodes — and links SAs back to the pods running them.

### Network Exposure (5 checks)

| ID | Finding | Severity |
|---|---|---|
| `NET-LB-OPEN` | LoadBalancer without `loadBalancerSourceRanges` | High |
| `NET-EXTERNAL-IP` | Service with `externalIPs` | High |
| `NET-INGRESS-NO-TLS` | Ingress without TLS | High |
| `NET-NODEPORT` | Service exposed via NodePort | Medium |
| `NET-INGRESS-WILDCARD` | Ingress with wildcard host | Medium |

### Node Security (2 checks)

| ID | Finding | Severity |
|---|---|---|
| `NODE-KUBELET-RO` | Kubelet read-only port 10255 reachable | Critical |
| `NODE-KUBELET-API` | Kubelet API port 10250 reachable | Medium |

Node probes run concurrently for fast scanning across large clusters.

### Secrets (3 checks)

| ID | Finding | Severity |
|---|---|---|
| `SECRET-SENSITIVE` | Opaque secret contains credential-like keys | Medium |
| `SECRET-DOCKER-HUB` | Docker Hub credentials in secret | Medium |
| `SECRET-TLS-MANUAL` | TLS secret not managed by cert-manager | Low |

### Policy & PSS (2 checks)

| ID | Finding | Severity |
|---|---|---|
| `POLICY-NONE` | No policy engine (Kyverno/Gatekeeper) detected | High |
| `PSS-NOT-ENFORCED` | Namespace lacks Pod Security Admission labels | High/Info |

System namespaces (`kube-system`, etc.) are flagged at `info` severity with tailored remediation.

## Usage

```
kuberoast [OPTIONS]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--report {json,text,html,sarif,junit,csv}` | `json` | Output format |
| `--out FILE` | — | Write report to file (required for `html`, `sarif`, `junit`, `csv`) |
| `--manifests PATH` | — | Scan a directory or file of YAML/JSON manifests instead of a live cluster |
| `--kubeconfig PATH` | — | Path to kubeconfig (defaults to `~/.kube/config`) |
| `-n, --namespace NS` | — | Limit scan to a single namespace |
| `--min-severity {info,low,medium,high,critical}` | `info` | Filter out findings below this severity |
| `--fail-on {info,low,medium,high,critical}` | — | Exit code 1 if any finding meets this threshold |
| `--no-compliance` | `false` | Skip CIS / MITRE ATT&CK / CWE enrichment |
| `--skip-nodes` | `false` | Skip kubelet port probes |
| `--skip-secrets` | `false` | Skip secret inspection |
| `--skip-attack-paths` | `false` | Skip RBAC attack-path analysis |
| `--provider {generic,eks,aks,gke}` | `generic` | Cloud provider hint for remediation wording |
| `-v, --verbose` | `false` | Progress logging to stderr |
| `-q, --quiet` | `false` | Suppress non-error logging |
| `--version` | — | Print version and exit |

### Examples

**Quick text scan of the default namespace:**
```bash
kuberoast -n default --report text
```

**Full cluster scan, only high and critical:**
```bash
kuberoast --min-severity high --report text
```

**HTML report for the security team:**
```bash
kuberoast --report html --out report.html
```

**CI gate — fail the pipeline on critical findings:**
```bash
kuberoast --fail-on critical --report json > results.json
```

**Verbose scan, skip node probes (faster):**
```bash
kuberoast -v --skip-nodes --report text
```

**Offline scan of a manifest directory (no cluster needed):**
```bash
kuberoast --manifests ./k8s --report text
```

**SARIF for GitHub code scanning:**
```bash
kuberoast --manifests ./k8s --report sarif --out kuberoast.sarif
```

**JUnit XML for Jenkins / GitLab / CircleCI test reports:**
```bash
kuberoast --report junit --out kuberoast.xml
```

## CI/CD Integration

KubeRoast is designed to gate deployments. Use `--fail-on` to set the threshold:

```yaml
# GitHub Actions — scan manifests in a PR and upload SARIF to code scanning
- uses: actions/checkout@v4

- name: Install KubeRoast
  run: pip install kuberoast

- name: Scan manifests
  run: |
    kuberoast --manifests ./k8s --report sarif --out kuberoast.sarif
    kuberoast --manifests ./k8s --fail-on high --report json > /dev/null

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: kuberoast.sarif
    category: kuberoast
```

A ready-to-run version of this workflow lives at
[`.github/workflows/security-scan.yml`](./.github/workflows/security-scan.yml).

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings at or above `--fail-on` threshold |
| `1` | Findings met or exceeded `--fail-on` threshold |
| `2` | Usage error or runtime failure |

## Output Formats

### JSON (default)
Machine-readable array of findings. Pipe to `jq` for filtering:
```bash
kuberoast | jq '[.[] | select(.severity == "critical")]'
```

### Text
Grouped by severity, with summary line and remediation per finding:
```
=== kuberoast scan: 12 findings (3 critical, 4 high, 5 medium) ===

--- CRITICAL (3) ---
  [CRITICAL] Privileged container
    Resource:    pod/prod/web-0::nginx
    Description: Container runs in privileged mode, granting broad access to the host kernel.
    Remediation: Remove privileged=true. Grant narrow capabilities only if needed.
```

### HTML
Dark-themed report with severity stat cards, severity badges, and CIS/MITRE/CWE chips per finding. Open in any browser:
```bash
kuberoast --report html --out report.html && open report.html
```

### SARIF
[SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) for GitHub code scanning, Azure DevOps, and any tool that consumes the standard. Severity is mapped to SARIF `level` (critical/high → `error`, medium → `warning`, low/info → `note`) and a `security-severity` score:
```bash
kuberoast --report sarif --out kuberoast.sarif
```

### JUnit XML
For Jenkins, GitLab, CircleCI, and other CI test dashboards. Findings are grouped by category as test suites; critical findings emit `<error>`, high findings emit `<failure>`:
```bash
kuberoast --report junit --out kuberoast.xml
```

### CSV
Flat tabular output with `id, severity, title, category, namespace, resource, description, remediation, cis_controls, mitre_attack, cwe, references`:
```bash
kuberoast --report csv --out kuberoast.csv
```

## Findings Schema

Every finding follows a structured format and is automatically enriched with industry-standard control mappings:

```json
{
  "id": "POD-PRIV",
  "title": "Privileged container",
  "description": "Container runs in privileged mode, granting broad access to the host kernel.",
  "severity": "critical",
  "category": "Pod Security",
  "namespace": "prod",
  "resource": "pod/web-0::nginx",
  "metadata": {},
  "remediation": "Remove privileged=true. Grant narrow capabilities only if needed.",
  "references": ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
  "cis_controls": ["CIS-K8s-5.2.1", "CIS-K8s-5.2.2"],
  "mitre_attack": ["T1611", "T1610"],
  "cwe": ["CWE-250", "CWE-269"]
}
```

**Severity levels:** `critical` > `high` > `medium` > `low` > `info`

**Categories:** Pod Security, RBAC, AttackPath, Network, Node, Secrets, Policy

### Compliance mappings

Every finding ID is mapped in [`kuberoast/utils/compliance.py`](./kuberoast/utils/compliance.py) to:

- **CIS Kubernetes Benchmark v1.9** controls (e.g. `5.2.1` for privileged containers)
- **MITRE ATT&CK for Containers** techniques (e.g. `T1611` Escape to Host)
- **CWE** weakness IDs (e.g. `CWE-250` Execution with Unnecessary Privileges)

Disable enrichment with `--no-compliance` if you need raw findings.

## Kubernetes RBAC

KubeRoast only needs **read access**. Apply this minimal ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kuberoast-reader
rules:
  - apiGroups: [""]
    resources: [pods, secrets, nodes, namespaces, services]
    verbs: [get, list, watch]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [roles, rolebindings, clusterroles, clusterrolebindings]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [get, list, watch]
  - apiGroups: [apiextensions.k8s.io]
    resources: [customresourcedefinitions]
    verbs: [get, list, watch]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kuberoast
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kuberoast-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kuberoast-reader
subjects:
  - kind: ServiceAccount
    name: kuberoast
    namespace: default
```

Secrets and nodes are optional — KubeRoast continues gracefully if those APIs return 401/403.

## Architecture

```
kuberoast/
  cli.py                      # CLI entry point, arg parsing, orchestration
  utils/
    findings.py               # Pydantic Finding model (with CIS/MITRE/CWE fields)
    compliance.py             # CIS K8s / MITRE ATT&CK / CWE mappings per finding ID
    manifests.py              # Offline YAML/JSON manifest loader
    kube.py                   # K8s API clients, pagination, error handling
  scanners/
    pods.py                   # 11 pod-level security checks
    rbac.py                   # 5 RBAC hygiene checks
    network.py                # Service + Ingress exposure checks
    nodes.py                  # Concurrent kubelet port probes
    secrets.py                # Credential heuristics
    policy.py                 # Policy engine (Kyverno/Gatekeeper) detection
    pss.py                    # Pod Security Standards label checks
    shared.py                 # Container iteration helpers
  attackpaths/
    rbac_escalation.py        # RBAC privilege escalation graph
  reporting/
    json.py                   # JSON output
    text.py                   # Severity-grouped text output
    html.py                   # Dark-themed HTML report with stat cards
    sarif.py                  # SARIF v2.1.0 (GitHub code scanning)
    junit.py                  # JUnit XML (CI test dashboards)
    csv_report.py             # CSV (analytics / spreadsheets)
tests/
  test_pods.py                # Pod scanner unit tests
  test_rbac.py                # RBAC scanner unit tests
  test_network.py             # Network scanner unit tests
  test_secrets.py             # Secret scanner unit tests
  test_pss.py                 # PSS scanner unit tests
  test_compliance.py          # Compliance enrichment tests
  test_sarif.py               # SARIF level/score/tag tests
  test_sarif_schema.py        # SARIF validated against official OASIS schema
  test_junit_csv.py           # JUnit and CSV output tests
  test_manifests.py           # Offline manifest loading tests
  test_property_manifests.py  # Hypothesis property-based fuzzing
  test_scanner_contracts.py   # Cross-scanner Finding-shape contract tests
  test_severity_matrix.py     # --fail-on / --min-severity matrix
  test_e2e_examples.py        # Golden tests against examples/
  test_performance.py         # Perf regression (1000 pods etc.)
  test_cli.py                 # CLI flag, exit-code, and end-to-end tests
  test_reporting.py           # Output format tests
  fixtures/
    sarif-2.1.0-schema.json   # OASIS SARIF v2.1.0 schema (bundled)
.github/workflows/
  ci.yml                      # Test matrix (3.9–3.12), ruff, build, Docker
  security-scan.yml           # Example: scan manifests + upload SARIF
Dockerfile                    # Non-root multi-stage container image
Makefile                      # install / dev / test / coverage / lint / build / docker
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `403/401` on some APIs | KubeRoast continues with partial results. Add RBAC permissions above. |
| No cluster found | Check `KUBECONFIG` or run `kubectl config get-contexts` |
| HTML requires `--out` | `kuberoast --report html --out report.html` |
| Slow on large clusters | Use `--skip-secrets`, `--skip-nodes`, or `-n <namespace>` to scope down |
| Node probes timing out | Kubelet ports may be firewalled. Use `--skip-nodes` |

## Roadmap

Shipped in 0.3.0:
- ✅ CIS Kubernetes Benchmark tagging
- ✅ MITRE ATT&CK technique tags per finding
- ✅ CWE weakness IDs per finding
- ✅ Offline manifest scanning (`--manifests`)
- ✅ Dockerfile for containerized scanning
- ✅ SARIF / JUnit / CSV output

Next:
- Provider-specific remediation (EKS / AKS / GKE)
- Gatekeeper / Kyverno policy inventory & drift
- NetworkPolicy gap detection
- Helm-chart values rendering for `--manifests`

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide. The short version:

1. Add/update unit tests for each new rule (`make test`)
2. Ground severities in public guidance or reproducible attacker tradecraft
3. Map new finding IDs to CIS / MITRE / CWE in `kuberoast/utils/compliance.py`
4. Keep remediation text explicit and actionable
5. Run `make lint` and `make test` before submitting

To report a security issue, see [SECURITY.md](./SECURITY.md).

## License

MIT — see [LICENSE](./LICENSE).

---

<p align="center">
  Built by <a href="https://github.com/SnailSploit">SnailSploit</a> / Kai Aizen
</p>
