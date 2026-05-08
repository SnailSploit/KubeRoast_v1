from typing import List, Set

from ..utils.findings import Finding

PSS_LABELS = [
    "pod-security.kubernetes.io/enforce",
    "pod-security.kubernetes.io/enforce-version",
    "pod-security.kubernetes.io/audit",
    "pod-security.kubernetes.io/audit-version",
    "pod-security.kubernetes.io/warn",
    "pod-security.kubernetes.io/warn-version",
]

# System namespaces where PSS is expected to be absent or privileged
SYSTEM_NAMESPACES: Set[str] = {"kube-system", "kube-public", "kube-node-lease"}


def scan_namespace_pss(nslist) -> List[Finding]:
    findings: List[Finding] = []
    for ns in nslist:
        ns_name = ns.metadata.name
        labels = (ns.metadata.labels or {})
        if not any(label in labels for label in PSS_LABELS):
            is_system = ns_name in SYSTEM_NAMESPACES
            findings.append(Finding(
                id="PSS-NOT-ENFORCED",
                title="PSS/PSA not labeled on namespace",
                description=f"Namespace '{ns_name}' lacks Pod Security Admission labels.",
                severity="info" if is_system else "high",
                category="Policy",
                resource=f"namespace/{ns_name}",
                remediation=(
                    "System namespace — PSS enforcement may conflict with control-plane components. "
                    "Consider audit/warn mode." if is_system else
                    "Label namespaces with PSS levels (enforce/audit/warn). Prefer 'restricted' for most workloads."
                ),
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
            ))
    return findings
