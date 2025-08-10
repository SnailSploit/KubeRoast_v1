from typing import List
from ..utils.findings import Finding

PSS_LABELS = [
    "pod-security.kubernetes.io/enforce",
    "pod-security.kubernetes.io/enforce-version",
    "pod-security.kubernetes.io/audit",
    "pod-security.kubernetes.io/audit-version",
    "pod-security.kubernetes.io/warn",
    "pod-security.kubernetes.io/warn-version",
]

def scan_namespace_pss(nslist) -> List[Finding]:
    findings: List[Finding] = []
    for ns in nslist:
        labels = (ns.metadata.labels or {})
        if not any(l in labels for l in PSS_LABELS):
            findings.append(Finding(
                id="PSS-NOT-ENFORCED",
                title="PSS/PSA not labeled on namespace",
                description=f"Namespace '{ns.metadata.name}' lacks Pod Security Admission labels.",
                severity="high", category="Policy",
                resource=f"namespace/{ns.metadata.name}",
                remediation="Label namespaces with PSS levels (enforce/audit/warn). Prefer 'restricted' for most workloads.",
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
            ))
    return findings
