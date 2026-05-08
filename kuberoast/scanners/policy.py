from typing import List

from ..utils.findings import Finding

POLICY_ENGINE_CRDS = {
    "kyverno": ["clusterpolicies.kyverno.io", "policies.kyverno.io"],
    "gatekeeper": ["configs.config.gatekeeper.sh", "constrainttemplates.templates.gatekeeper.sh"],
    "opa": ["constraints.constraints.gatekeeper.sh"],
}

def scan_policy_engines(crds) -> List[Finding]:
    """Detect presence of policy engines (Kyverno, Gatekeeper, OPA)."""
    findings: List[Finding] = []

    if not crds:
        findings.append(Finding(
            id="POLICY-NONE",
            title="No policy engine detected",
            description="Neither Kyverno nor Gatekeeper CRDs are present. Policy enforcement is likely not enabled.",
            severity="high",
            category="Policy",
            remediation="Install and configure a policy engine like Kyverno or Gatekeeper to enforce security policies across the cluster.",
            references=[
                "https://kyverno.io/",
                "https://open-policy-agent.github.io/gatekeeper/"
            ]
        ))
        return findings

    crd_names = {crd.metadata.name for crd in crds}

    engines_found = []
    for engine, expected_crds in POLICY_ENGINE_CRDS.items():
        if any(crd_name in crd_names for crd_name in expected_crds):
            engines_found.append(engine)

    if not engines_found:
        findings.append(Finding(
            id="POLICY-NONE",
            title="No policy engine detected",
            description="Neither Kyverno nor Gatekeeper CRDs are present. Policy enforcement is likely not enabled.",
            severity="high",
            category="Policy",
            remediation="Install and configure a policy engine like Kyverno or Gatekeeper to enforce security policies across the cluster.",
            references=[
                "https://kyverno.io/",
                "https://open-policy-agent.github.io/gatekeeper/"
            ]
        ))

    return findings
