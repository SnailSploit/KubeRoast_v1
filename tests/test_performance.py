"""Performance regression tests.

These guard against accidental O(n²) regressions in the scanners. The
thresholds are intentionally generous so they don't go red on slow CI
runners — they're meant to catch order-of-magnitude regressions, not
small slowdowns.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from kuberoast.attackpaths.rbac_escalation import analyze_attack_paths
from kuberoast.reporting import csv_report
from kuberoast.reporting import json as json_report
from kuberoast.reporting import sarif as sarif_report
from kuberoast.scanners.pods import scan_pod_security
from kuberoast.scanners.rbac import scan_rbac
from kuberoast.utils.compliance import enrich_findings
from tests.conftest import (
    make_binding,
    make_container,
    make_pod,
    make_role,
    make_rule,
    make_subject,
)

pytestmark = pytest.mark.performance


def _bench(fn, *args, **kwargs):
    start = time.perf_counter()
    out = fn(*args, **kwargs)
    return out, time.perf_counter() - start


def _gen_pods(n: int) -> list:
    pods = []
    for i in range(n):
        pods.append(
            make_pod(
                name=f"pod-{i}",
                namespace=f"ns-{i % 20}",
                containers=[make_container(name=f"c-{i}", privileged=(i % 5 == 0))],
            )
        )
    return pods


@pytest.mark.parametrize("n,limit_seconds", [(100, 1.0), (1000, 5.0)])
def test_scan_pods_scales_linearly(n: int, limit_seconds: float):
    pods = _gen_pods(n)
    findings = []
    _, elapsed = _bench(lambda: [findings.extend(scan_pod_security(p)) for p in pods])
    assert elapsed < limit_seconds, f"scanning {n} pods took {elapsed:.2f}s (>{limit_seconds}s)"
    assert findings


def test_rbac_scanner_scales_to_large_cluster():
    """500 roles + 500 cluster role bindings should finish well under 5s."""
    roles = [
        make_role(
            name=f"r-{i}",
            namespace="default",
            rules=[make_rule(verbs=["get", "list"], resources=["pods"])],
        )
        for i in range(500)
    ]
    crbs = [
        make_binding(
            name=f"crb-{i}",
            role_kind="ClusterRole",
            role_name="view",
            subjects=[make_subject(kind="ServiceAccount", name=f"sa-{i}", namespace="default")],
        )
        for i in range(500)
    ]
    _, elapsed = _bench(scan_rbac, roles, [], [], crbs)
    assert elapsed < 5.0, f"RBAC scan took {elapsed:.2f}s on 500+500"


def test_attack_path_analysis_handles_many_principals():
    """Attack-path analysis should be sub-linear-ish on a sparse principal graph."""
    role = make_role(rules=[make_rule(verbs=["create", "get"], resources=["pods", "secrets"])])
    crbs = [
        make_binding(
            name=f"crb-{i}",
            role_kind="ClusterRole",
            role_name=f"r-{i}",
            subjects=[make_subject(kind="ServiceAccount", name=f"sa-{i}", namespace=f"ns-{i % 20}")],
        )
        for i in range(200)
    ]
    pods = _gen_pods(200)
    _, elapsed = _bench(analyze_attack_paths, [role], [], [], crbs, pods)
    assert elapsed < 5.0, f"attack-path analysis took {elapsed:.2f}s"


def test_compliance_enrichment_is_fast_on_many_findings():
    pods = _gen_pods(1000)
    findings = []
    for p in pods:
        findings.extend(scan_pod_security(p))
    _, elapsed = _bench(enrich_findings, findings)
    assert elapsed < 1.0, f"compliance enrichment of {len(findings)} findings took {elapsed:.2f}s"


def test_json_emit_scales():
    pods = _gen_pods(1000)
    findings = []
    for p in pods:
        findings.extend(scan_pod_security(p))
    _, elapsed = _bench(json_report.emit, findings)
    assert elapsed < 2.0


def test_sarif_emit_scales():
    pods = _gen_pods(500)
    findings = []
    for p in pods:
        findings.extend(scan_pod_security(p))
    enrich_findings(findings)
    _, elapsed = _bench(sarif_report.emit, findings)
    assert elapsed < 2.0


def test_csv_emit_scales():
    pods = _gen_pods(1000)
    findings = []
    for p in pods:
        findings.extend(scan_pod_security(p))
    _, elapsed = _bench(csv_report.emit, findings)
    assert elapsed < 1.0


def test_empty_inputs_are_instant():
    """Empty-input fast path must stay O(1)."""
    _, elapsed = _bench(scan_pod_security, SimpleNamespace(
        metadata=SimpleNamespace(name="x", namespace="x", annotations={}),
        spec=SimpleNamespace(
            containers=[], init_containers=[], ephemeral_containers=[],
            host_network=False, host_pid=False, host_ipc=False,
            automount_service_account_token=False,
            volumes=[], service_account_name="default",
            security_context=SimpleNamespace(seccomp_profile=None),
        ),
    ))
    assert elapsed < 0.01
