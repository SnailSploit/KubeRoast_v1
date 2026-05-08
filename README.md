<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/tests-38%20passed-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/version-0.2.0-orange?style=flat-square" alt="Version">
</p>

<h1 align="center">KubeRoast</h1>

<p align="center">
  <strong>Red-team Kubernetes misconfiguration & attack-path scanner</strong><br>
  Fast, opinionated, read-only. Built for real-world escalation paths.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-it-finds">What It Finds</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#cicd-integration">CI/CD</a> &bull;
  <a href="#output-formats">Output</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

> **Ethical use only.** Run KubeRoast only on clusters you own or have explicit written permission to test.

## Why KubeRoast

Most Kubernetes security scanners generate noise. KubeRoast focuses on **what actually gets you owned** — privilege escalation paths, exposed kubelets, over-permissioned RBAC, network services open to the internet, and secrets sitting in plain sight. It reads, never writes. Safe to run in production.

## Quick Start

```bash
# Install
git clone https://github.com/SnailSploit/KubeRoast_v1.git
cd KubeRoast_v1
pip install -e .

# Scan your cluster
kuberoast --report text
```

That's it. KubeRoast picks up your current kubeconfig context automatically.

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
| `--report {json,text,html}` | `json` | Output format |
| `--out FILE` | — | Write report to file (required for HTML) |
| `--kubeconfig PATH` | — | Path to kubeconfig (defaults to `~/.kube/config`) |
| `-n, --namespace NS` | — | Limit scan to a single namespace |
| `--min-severity {info,low,medium,high,critical}` | `info` | Filter out findings below this severity |
| `--fail-on {info,low,medium,high,critical}` | — | Exit code 1 if any finding meets this threshold |
| `--skip-nodes` | `false` | Skip kubelet port probes |
| `--skip-secrets` | `false` | Skip secret inspection |
| `--skip-attack-paths` | `false` | Skip RBAC attack-path analysis |
| `--provider {generic,eks,aks,gke}` | `generic` | Cloud provider hint for remediation wording |
| `-v, --verbose` | `false` | Progress logging to stderr |

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

## CI/CD Integration

KubeRoast is designed to gate deployments. Use `--fail-on` to set the threshold:

```yaml
# GitHub Actions example
- name: Security scan
  run: |
    pip install -e .
    kuberoast --fail-on high --report json > kuberoast-results.json
```

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
Dark-themed report with severity badges, sortable table, and remediation guidance. Open in any browser:
```bash
kuberoast --report html --out report.html && open report.html
```

## Findings Schema

Every finding follows a structured format:

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
  "references": ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
}
```

**Severity levels:** `critical` > `high` > `medium` > `low` > `info`

**Categories:** Pod Security, RBAC, AttackPath, Network, Node, Secrets, Policy

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
    findings.py               # Pydantic Finding model
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
    html.py                   # Dark-themed HTML report
tests/
  test_pods.py                # Pod scanner unit tests
  test_rbac.py                # RBAC scanner unit tests
  test_network.py             # Network scanner unit tests
  test_secrets.py             # Secret scanner unit tests
  test_pss.py                 # PSS scanner unit tests
  test_reporting.py           # Output format tests
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

- CIS Kubernetes Benchmark tagging
- Provider-specific remediation (EKS/AKS/GKE)
- Offline manifest scanning (`--manifests`)
- Gatekeeper/Kyverno policy inventory & drift
- MITRE ATT&CK technique tags per finding
- Dockerfile for containerized scanning

## Contributing

PRs welcome. Please:

1. Add/update unit tests for each new rule
2. Ground severities in public guidance or reproducible attacker tradecraft
3. Keep remediation text explicit and actionable
4. Run `pytest` before submitting

## License

MIT — see [LICENSE](./LICENSE).

---

<p align="center">
  Built by <a href="https://github.com/SnailSploit">SnailSploit</a> / Kai Aizen
</p>

<!-- snailsploit-backlink:start -->

---

## 📚 Documentation & Author

This project's full writeup, methodology, and related research lives at:

**[https://snailsploit.com/tools](https://snailsploit.com/tools)**

Created by **Kai Aizen** — independent offensive security researcher.

[snailsploit.com](https://snailsploit.com) · [Research](https://snailsploit.com/research) · [Frameworks](https://snailsploit.com/frameworks) · [GitHub](https://github.com/SnailSploit) · [LinkedIn](https://linkedin.com/in/kaiaizen) · [ResearchGate](https://www.researchgate.net/profile/Kai-Aizen-2) · [X/Twitter](https://x.com/SnailSploit)

> *Same attack. Different substrate.*

<!-- snailsploit-backlink:end -->
