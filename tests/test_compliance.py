from kuberoast.utils.compliance import COMPLIANCE_MAP, enrich_finding, enrich_findings
from kuberoast.utils.findings import Finding


def test_known_finding_enriched():
    f = Finding(id="POD-PRIV", title="Privileged container", description="x", severity="critical")
    enrich_finding(f)
    assert any(c.startswith("CIS-K8s-") for c in f.cis_controls)
    assert "T1611" in f.mitre_attack
    assert any(c.startswith("CWE-") for c in f.cwe)


def test_unknown_finding_passthrough():
    f = Finding(id="UNKNOWN-CHECK", title="x", description="y", severity="low")
    enrich_finding(f)
    assert f.cis_controls == []
    assert f.mitre_attack == []
    assert f.cwe == []


def test_enrich_findings_handles_list():
    findings = [
        Finding(id="POD-PRIV", title="x", description="y", severity="critical"),
        Finding(id="RBAC-CLUSTER-ADMIN", title="x", description="y", severity="critical"),
        Finding(id="UNKNOWN", title="x", description="y", severity="low"),
    ]
    enrich_findings(findings)
    assert findings[0].cis_controls
    assert findings[1].cis_controls
    assert findings[2].cis_controls == []


def test_existing_compliance_not_overwritten():
    f = Finding(
        id="POD-PRIV",
        title="x",
        description="y",
        severity="critical",
        cis_controls=["CUSTOM-1"],
    )
    enrich_finding(f)
    assert f.cis_controls == ["CUSTOM-1"]


def test_compliance_map_covers_all_known_ids():
    """Sanity check that key finding IDs have compliance mappings."""
    expected_ids = {
        "POD-PRIV", "POD-ROOT", "POD-PE", "POD-HOSTNS", "POD-CAPS",
        "POD-HOSTPATH", "POD-RWFS", "POD-NO-SECCOMP", "POD-NO-LIMITS",
        "POD-SATOKEN", "POD-NO-APPARMOR",
        "RBAC-ANON", "RBAC-CLUSTER-ADMIN", "RBAC-ESCALATION-VERB",
        "RBAC-WILDCARD", "RBAC-SENSITIVE-WRITE", "RBAC-BROAD-GROUP",
        "AP-RBAC-ESC",
        "NET-LB-OPEN", "NET-EXTERNAL-IP", "NET-INGRESS-NO-TLS",
        "NET-NODEPORT", "NET-INGRESS-WILDCARD",
        "NODE-KUBELET-RO", "NODE-KUBELET-API",
        "SECRET-SENSITIVE", "SECRET-DOCKER-HUB", "SECRET-TLS-MANUAL",
        "POLICY-NONE", "PSS-NOT-ENFORCED",
    }
    missing = expected_ids - set(COMPLIANCE_MAP.keys())
    assert not missing, f"Missing compliance mappings for: {missing}"
