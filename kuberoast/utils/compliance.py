"""Compliance framework mappings: CIS Kubernetes Benchmark, MITRE ATT&CK, CWE.

Mappings follow:
- CIS Kubernetes Benchmark v1.9 (https://www.cisecurity.org/benchmark/kubernetes)
- MITRE ATT&CK for Containers (https://attack.mitre.org/matrices/enterprise/containers/)
- Common Weakness Enumeration (https://cwe.mitre.org/)
"""
from typing import Dict, List

# Map kuberoast finding IDs to industry-standard frameworks.
# Each entry: (cis_controls, mitre_attack_techniques, cwe_ids)
COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {
    # Pod Security
    "POD-PRIV": {
        "cis": ["5.2.1", "5.2.2"],
        "mitre": ["T1611", "T1610"],
        "cwe": ["CWE-250", "CWE-269"],
    },
    "POD-ROOT": {
        "cis": ["5.2.6"],
        "mitre": ["T1611"],
        "cwe": ["CWE-250"],
    },
    "POD-PE": {
        "cis": ["5.2.5"],
        "mitre": ["T1611", "T1548"],
        "cwe": ["CWE-269"],
    },
    "POD-HOSTNS": {
        "cis": ["5.2.2", "5.2.3", "5.2.4"],
        "mitre": ["T1611"],
        "cwe": ["CWE-668"],
    },
    "POD-CAPS": {
        "cis": ["5.2.8", "5.2.9"],
        "mitre": ["T1611"],
        "cwe": ["CWE-250"],
    },
    "POD-HOSTPATH": {
        "cis": ["5.2.10"],
        "mitre": ["T1611", "T1610"],
        "cwe": ["CWE-552"],
    },
    "POD-RWFS": {
        "cis": ["5.2.12"],
        "mitre": ["T1611"],
        "cwe": ["CWE-732"],
    },
    "POD-NO-SECCOMP": {
        "cis": ["5.7.2"],
        "mitre": ["T1611"],
        "cwe": ["CWE-693"],
    },
    "POD-NO-LIMITS": {
        "cis": ["5.1.5"],
        "mitre": ["T1499"],
        "cwe": ["CWE-770"],
    },
    "POD-SATOKEN": {
        "cis": ["5.1.5", "5.1.6"],
        "mitre": ["T1528"],
        "cwe": ["CWE-732"],
    },
    "POD-NO-APPARMOR": {
        "cis": ["5.7.3"],
        "mitre": ["T1611"],
        "cwe": ["CWE-693"],
    },
    # RBAC
    "RBAC-ANON": {
        "cis": ["5.1.1", "5.1.2"],
        "mitre": ["T1078"],
        "cwe": ["CWE-287", "CWE-862"],
    },
    "RBAC-CLUSTER-ADMIN": {
        "cis": ["5.1.1", "5.1.3"],
        "mitre": ["T1078.004"],
        "cwe": ["CWE-269"],
    },
    "RBAC-ESCALATION-VERB": {
        "cis": ["5.1.1"],
        "mitre": ["T1548", "T1098"],
        "cwe": ["CWE-269", "CWE-285"],
    },
    "RBAC-WILDCARD": {
        "cis": ["5.1.3"],
        "mitre": ["T1078"],
        "cwe": ["CWE-732"],
    },
    "RBAC-SENSITIVE-WRITE": {
        "cis": ["5.1.1", "5.1.4"],
        "mitre": ["T1098", "T1552.007"],
        "cwe": ["CWE-285"],
    },
    "RBAC-BROAD-GROUP": {
        "cis": ["5.1.1", "5.1.2"],
        "mitre": ["T1078"],
        "cwe": ["CWE-732"],
    },
    # Attack Path
    "AP-RBAC-ESC": {
        "cis": ["5.1.1"],
        "mitre": ["T1548", "T1098", "T1078.004"],
        "cwe": ["CWE-269"],
    },
    # Network
    "NET-LB-OPEN": {
        "cis": ["5.3.2"],
        "mitre": ["T1190"],
        "cwe": ["CWE-668"],
    },
    "NET-EXTERNAL-IP": {
        "cis": ["5.3.2"],
        "mitre": ["T1190"],
        "cwe": ["CWE-668"],
    },
    "NET-INGRESS-NO-TLS": {
        "cis": ["5.3.2"],
        "mitre": ["T1040"],
        "cwe": ["CWE-319"],
    },
    "NET-NODEPORT": {
        "cis": ["5.3.2"],
        "mitre": ["T1190"],
        "cwe": ["CWE-668"],
    },
    "NET-INGRESS-WILDCARD": {
        "cis": ["5.3.2"],
        "mitre": ["T1190"],
        "cwe": ["CWE-668"],
    },
    # Node
    "NODE-KUBELET-RO": {
        "cis": ["4.2.4"],
        "mitre": ["T1133", "T1190"],
        "cwe": ["CWE-306"],
    },
    "NODE-KUBELET-API": {
        "cis": ["4.2.1", "4.2.2", "4.2.3"],
        "mitre": ["T1133"],
        "cwe": ["CWE-306"],
    },
    # Secrets
    "SECRET-SENSITIVE": {
        "cis": ["5.4.1"],
        "mitre": ["T1552.001", "T1552.007"],
        "cwe": ["CWE-798", "CWE-256"],
    },
    "SECRET-DOCKER-HUB": {
        "cis": ["5.4.1"],
        "mitre": ["T1552.001"],
        "cwe": ["CWE-798"],
    },
    "SECRET-TLS-MANUAL": {
        "cis": ["5.4.2"],
        "mitre": ["T1552.004"],
        "cwe": ["CWE-321"],
    },
    # Policy
    "POLICY-NONE": {
        "cis": ["5.2.1"],
        "mitre": ["T1610"],
        "cwe": ["CWE-693"],
    },
    "PSS-NOT-ENFORCED": {
        "cis": ["5.2.1"],
        "mitre": ["T1611"],
        "cwe": ["CWE-693"],
    },
}


def enrich_finding(finding) -> None:
    """Mutate a Finding in place to add CIS, MITRE ATT&CK, and CWE mappings."""
    mapping = COMPLIANCE_MAP.get(finding.id)
    if not mapping:
        return
    if not finding.cis_controls:
        finding.cis_controls = [f"CIS-K8s-{c}" for c in mapping.get("cis", [])]
    if not finding.mitre_attack:
        finding.mitre_attack = list(mapping.get("mitre", []))
    if not finding.cwe:
        finding.cwe = list(mapping.get("cwe", []))


def enrich_findings(findings) -> None:
    """Enrich a list of findings with compliance metadata."""
    for f in findings:
        enrich_finding(f)
