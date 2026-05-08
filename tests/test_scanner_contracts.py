"""Contract tests: every scanner produces well-formed Findings.

These tests guard against drift in the Finding schema and ensure that all
scanner outputs are consistent: stable IDs, valid severities, non-empty
descriptions, and (for known IDs) matching compliance metadata.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

import pytest

from kuberoast.attackpaths.rbac_escalation import analyze_attack_paths
from kuberoast.scanners.network import scan_ingresses, scan_services
from kuberoast.scanners.pods import scan_pod_security
from kuberoast.scanners.policy import scan_policy_engines
from kuberoast.scanners.pss import scan_namespace_pss
from kuberoast.scanners.rbac import scan_rbac
from kuberoast.scanners.secrets import scan_secrets
from kuberoast.utils.compliance import COMPLIANCE_MAP, enrich_findings
from kuberoast.utils.findings import SEVERITY_TO_CVSS, Finding
from tests.conftest import (
    make_binding,
    make_container,
    make_ingress,
    make_namespace,
    make_pod,
    make_role,
    make_rule,
    make_secret,
    make_service,
    make_subject,
)

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CATEGORIES = {"Pod Security", "RBAC", "AttackPath", "Network", "Node", "Secrets", "Policy", "general"}

# T#### or T####.### — MITRE technique format
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# CIS-K8s-X.Y or CIS-K8s-X.Y.Z
CIS_RE = re.compile(r"^CIS-K8s-\d+(\.\d+)+$")
# CWE-### or CWE-####
CWE_RE = re.compile(r"^CWE-\d+$")


def _comprehensive_findings() -> list:
    """Run every scanner against deliberately-bad fixtures to collect all IDs."""
    findings: list = []

    # Pods
    findings.extend(scan_pod_security(
        make_pod(
            host_network=True, host_pid=True, host_ipc=True,
            containers=[
                make_container(
                    privileged=True, run_as_user=0,
                    allow_privilege_escalation=True,
                    read_only_root_filesystem=False,
                    caps_add=["SYS_ADMIN", "NET_ADMIN"],
                ),
            ],
        )
    ))

    # Namespaces
    findings.extend(scan_namespace_pss([
        make_namespace(name="prod"),
        make_namespace(name="kube-system"),
    ]))

    # RBAC
    role = make_role(rules=[make_rule(verbs=["*", "escalate", "bind"], resources=["*", "secrets"])])
    crb = make_binding(
        role_kind="ClusterRole", role_name="cluster-admin",
        subjects=[make_subject(kind="User", name="system:anonymous")],
    )
    crb_group = make_binding(
        role_kind="ClusterRole", role_name="view",
        subjects=[make_subject(kind="Group", name="system:unauthenticated")],
    )
    findings.extend(scan_rbac([role], [], [], [crb, crb_group]))

    # Attack paths — give a principal a juicy permission set
    findings.extend(analyze_attack_paths([role], [], [], [crb], []))

    # Network
    findings.extend(scan_services([
        make_service(svc_type="LoadBalancer"),
        make_service(svc_type="NodePort"),
        make_service(svc_type="ClusterIP", external_ips=["1.2.3.4"]),
    ]))
    from types import SimpleNamespace
    findings.extend(scan_ingresses([
        make_ingress(),  # no TLS
        make_ingress(rules=[SimpleNamespace(host="*.example.com", http=None)]),
    ]))

    # Secrets
    import base64
    val = base64.b64encode(b"verysecretpassword").decode()
    findings.extend(scan_secrets([
        make_secret(data={"password": val}),
        make_secret(secret_type="kubernetes.io/tls"),
    ]))

    # Policy — empty CRD list to flag POLICY-NONE
    findings.extend(scan_policy_engines([]))

    return findings


@pytest.fixture(scope="module")
def all_findings():
    findings = _comprehensive_findings()
    enrich_findings(findings)
    assert findings, "test fixture should produce findings"
    return findings


def test_every_finding_is_a_finding_instance(all_findings):
    assert all(isinstance(f, Finding) for f in all_findings)


def test_every_finding_has_required_fields(all_findings):
    for f in all_findings:
        assert f.id and isinstance(f.id, str)
        assert f.title and len(f.title) > 3
        assert f.description and len(f.description) > 10
        assert f.severity in VALID_SEVERITIES


def test_every_finding_has_valid_category(all_findings):
    for f in all_findings:
        assert f.category in VALID_CATEGORIES, f"unknown category: {f.category!r} on {f.id}"


def test_every_finding_id_uses_namespaced_format(all_findings):
    """IDs should look like CATEGORY-SUBJECT (e.g. POD-PRIV, RBAC-ANON)."""
    for f in all_findings:
        assert "-" in f.id, f"finding id {f.id!r} is not namespaced"
        assert f.id == f.id.upper().replace("_", "-"), f"id {f.id!r} is not uppercase-dash"


def test_every_finding_has_remediation(all_findings):
    """Remediation is the whole point — every finding should have one."""
    missing = [f.id for f in all_findings if not f.remediation]
    assert not missing, f"findings without remediation: {missing}"


def test_known_ids_are_enriched(all_findings):
    enriched = [f for f in all_findings if f.id in COMPLIANCE_MAP]
    assert enriched, "expected at least one known-mapped finding"
    for f in enriched:
        assert f.cis_controls or f.mitre_attack or f.cwe, (
            f"{f.id} maps in COMPLIANCE_MAP but was not enriched"
        )


def test_mitre_technique_format(all_findings):
    for f in all_findings:
        for technique in f.mitre_attack:
            assert MITRE_RE.match(technique), f"bad MITRE id: {technique!r} on {f.id}"


def test_cis_control_format(all_findings):
    for f in all_findings:
        for control in f.cis_controls:
            assert CIS_RE.match(control), f"bad CIS id: {control!r} on {f.id}"


def test_cwe_format(all_findings):
    for f in all_findings:
        for cwe in f.cwe:
            assert CWE_RE.match(cwe), f"bad CWE id: {cwe!r} on {f.id}"


def test_compliance_map_internal_consistency():
    """Every entry in COMPLIANCE_MAP uses the documented format."""
    for finding_id, mapping in COMPLIANCE_MAP.items():
        for cis in mapping.get("cis", []):
            # Stored without the 'CIS-K8s-' prefix in the map
            assert re.match(r"^\d+(\.\d+)+$", cis), f"bad CIS in map for {finding_id}: {cis!r}"
        for technique in mapping.get("mitre", []):
            assert MITRE_RE.match(technique), f"bad MITRE in map for {finding_id}: {technique!r}"
        for cwe in mapping.get("cwe", []):
            assert CWE_RE.match(cwe), f"bad CWE in map for {finding_id}: {cwe!r}"


def test_severity_cvss_mapping():
    """SEVERITY_TO_CVSS exists and orders correctly."""
    assert SEVERITY_TO_CVSS["critical"] > SEVERITY_TO_CVSS["high"]
    assert SEVERITY_TO_CVSS["high"] > SEVERITY_TO_CVSS["medium"]
    assert SEVERITY_TO_CVSS["medium"] > SEVERITY_TO_CVSS["low"]
    assert SEVERITY_TO_CVSS["low"] >= SEVERITY_TO_CVSS["info"]


def test_scanner_signatures_return_lists():
    """All scanners return Iterable[Finding]."""
    callables = [
        (scan_pod_security, [make_pod()]),
        (scan_namespace_pss, [[make_namespace(name="x")]]),
        (scan_rbac, [[], [], [], []]),
        (scan_services, [[]]),
        (scan_ingresses, [[]]),
        (scan_secrets, [[]]),
        (scan_policy_engines, [[]]),
        (analyze_attack_paths, [[], [], [], [], []]),
    ]
    for fn, args in callables:
        out = fn(*args)
        assert isinstance(out, Iterable), f"{fn.__name__} returned non-iterable"
        for f in out:
            assert isinstance(f, Finding)


def test_finding_is_json_serializable(all_findings):
    """Pydantic dump must always succeed and be json-serializable."""
    import json
    for f in all_findings:
        d = f.model_dump()
        json.dumps(d)  # must not raise
