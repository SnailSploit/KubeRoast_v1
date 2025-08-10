````markdown ````
### Kuberoast
From-scratch, red-team–oriented **Kubernetes misconfiguration & attack-path scanner**. Fast, readable, and opinionated toward real-world escalation paths.

> ⚠️ **Ethical use only.** Run only on clusters you own or have explicit written permission to test.

---

## Table of contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Kubernetes auth](#kubernetes-auth)
- [Minimal RBAC (read-only)](#minimal-rbac-read-only)
- [Usage](#usage)
- [Flags](#flags)
- [Examples](#examples)
- [Findings schema](#findings-schema)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features
- **Read-only by default**: safe enumeration via Kubernetes API (in-cluster or `KUBECONFIG`).
- **Pod Security** misconfigs aligned with **Pod Security Standards** (privileged, root, allowPrivilegeEscalation, writable rootfs, host* namespaces, dangerous caps, hostPath, SA token).
- **RBAC hygiene**: wildcards, `cluster-admin` via bindings, and sensitive verbs/resources (`bind`, `escalate`, `impersonate`, `pods/exec`, `secrets`).
- **Attack-path modeling**: maps principals (esp. ServiceAccounts) to concrete escalation ability; links SAs to pods using them.
- **Network exposure**: Services (NodePort, LoadBalancer without `loadBalancerSourceRanges`, `externalIPs`), Ingress (no TLS, wildcard hosts).
- **Policy engines presence**: warns if neither **Kyverno** nor **Gatekeeper** CRDs are present.
- **Reports**: JSON, terminal-aligned Text, and dark-themed HTML (clean margins & padding).
- **Graceful RBAC handling**: partial results even when some APIs are 401/403.
````
---
````
## Requirements
- **Python**: 3.9+
- **Packages** (auto-installed via `pyproject.toml`):
  - `kubernetes`, `pydantic`, `typing-extensions`, `PyYAML`
- **Access**: a kube context or in-cluster SA with read permissions (see RBAC below).
````
---
````
## Installation

### A) From source (recommended for contributors)
```bash
git clone https://github.com/<you>/kuberoast2
cd kuberoast2
python -m pip install -e .
````
````
````
### B) User-wide with pipx

```bash
pipx install "git+https://github.com/<you>/kuberoast2.git"
```

> Tip: ensure your shell uses the right interpreter (`python -V`).

---

## Kubernetes auth

* **In-cluster**: when running inside a pod, in-cluster credentials are used.
* **Out-of-cluster**: `kubectl`-style auth via `KUBECONFIG` or default config (e.g., `~/.kube/config`).
* The active **context/namespace** is used unless you override.

---

## Minimal RBAC (read-only)

This policy is sufficient for most findings (cluster-wide list/watch). Tighten as needed.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kuberoast-reader
rules:
  - apiGroups: [""]
    resources: ["pods","secrets","nodes","namespaces","services"]
    verbs: ["get","list","watch"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles","rolebindings","clusterroles","clusterrolebindings"]
    verbs: ["get","list","watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get","list","watch"]
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["get","list","watch"]
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

> Secrets/nodes enumeration is optional; the tool continues if those APIs are forbidden.

---

## Usage

```bash
kuberoast [--report json|text|html] [--out FILE] \
          [--skip-nodes] [--skip-secrets] [--skip-attack-paths] \
          [--manifests DIR] [--provider generic|eks|aks|gke]
```

* **Cluster mode (default)**: connects using in-cluster credentials or your current kube-context.
* **Manifest mode**: `--manifests DIR` scans YAML/JSON (Pods & Pod templates, Services, Ingress) offline.
* **Reports**: `json` (machine-readable), `text` (aligned), `html` (polished dark theme; use `--out`).

---

## Flags

| Flag                  | Type / Values                        |   Default | Description                                                                     |
| --------------------- | ------------------------------------ | --------: | ------------------------------------------------------------------------------- |
| `--report`            | `json` \| `text` \| `html`           |    `json` | Output format. Use `--out` for HTML or to save to a file.                       |
| `--out`               | path                                 |         — | Write report to a file. **Required** for `--report html`.                       |
| `--skip-nodes`        | bool                                 |   `false` | Skip node/kubelet reachability probes (10255/10250).                            |
| `--skip-secrets`      | bool                                 |   `false` | Skip heuristic secret inspection.                                               |
| `--skip-attack-paths` | bool                                 |   `false` | Skip RBAC attack-path modeling.                                                 |
| `--manifests`         | dir                                  |         — | Enable **manifest mode** (offline scan of YAML/JSON).                           |
| `--provider`          | `generic` \| `eks` \| `aks` \| `gke` | `generic` | Tweak remediation wording for common managed platforms (informational for now). |

---

## Examples

### Cluster scan (text)

```bash
kuberoast --report text
```

```
SEVERITY  TITLE                                    RESOURCE                             DESCRIPTION
----------------------------------------------------------------------------------------------------
CRITICAL  Privileged container                     pod/prod/web-0::nginx               Container runs in privileged mode, granting broad access to the host kernel.
HIGH      Container runs as root (runAsUser=0)     pod/prod/web-0::nginx               Running as root increases blast radius if the container is compromised.
HIGH      RBAC permissions enable potential ...     sa:prod:deployer                    Principal 'sa:prod:deployer' can bind rolebindings; can exec/attach to pods.
MEDIUM    Kubelet API port 10250 reachable         node/ip-10-0-1-23                   Node exposes kubelet API; ensure TLS and authz are enforced.
```

### JSON output

```bash
kuberoast --report json > results.json
jq '.[0]' results.json
```

### HTML report

```bash
kuberoast --report html --out report.html
# open report.html  (macOS: `open report.html`)
```

### Manifest scan (GitOps/offline)

```bash
kuberoast --manifests ./k8s --report html --out manifest-report.html
```

---

## Findings schema

Each finding is emitted as a JSON object (keys may be absent when not applicable):

```json
{
  "id": "POD-PRIV",
  "title": "Privileged container",
  "description": "Container runs in privileged mode, granting broad access to the host kernel.",
  "severity": "critical",
  "category": "Pod Security",
  "namespace": "prod",
  "resource": "pod/web-0::nginx",
  "metadata": {"...": "..."},
  "remediation": "Remove privileged=true. Grant narrow capabilities only if needed.",
  "references": ["https://…"]
}
```

Categories currently include: `Pod Security`, `RBAC`, `AttackPath`, `Network`, `Policy`, `Secrets`, `Node`.

---

## Exit codes

* **0** — success
* **1** — runtime error
* **2** — usage error (e.g., `--report html` without `--out`)

---

## Troubleshooting

* **403/401 on some APIs** → The tool continues with partial results. Add/adjust RBAC (see above).
* **No clusters found** → Check `KUBECONFIG` or `kubectl config get-contexts`.
* **HTML requires --out** → `kuberoast --report html --out report.html`.
* **Large clusters** → Pagination is enabled; for speed use `--skip-secrets` and/or `--skip-nodes`.
* **Manifests** → Helm/kustomize-rendered output is best; raw templates may omit resolved values.

---

## Roadmap

* CIS Kubernetes Benchmark tagging in output.
* Provider-specific remediation tuning (EKS/AKS/GKE) and cloud-LB nuances.
* Service/Ingress enrichment (class, annotations; public dashboards detection).
* Gatekeeper/Kyverno policy inventory & drift (beyond CRD presence).
* Kubelet/control-plane flag inspection where accessible.
* MITRE ATT\&CK technique tags per finding.

---

## Contributing

PRs welcome! Please:

1. Add/update unit tests for each new rule.
2. Ground severities/remediations in public guidance or reproducible attacker tradecraft.
3. Keep remediation text explicit and actionable.

---

## License

MIT — see [`LICENSE`](./LICENSE).

```

::contentReference[oaicite:0]{index=0}
```
