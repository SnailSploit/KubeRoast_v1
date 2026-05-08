"""End-to-end golden tests against the bundled examples/ manifests.

These lock in the *expected* findings for the curated insecure samples so
regressions in any scanner show up loudly. Each example file is a known-bad
artifact whose findings should remain stable across refactors.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kuberoast.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _scan_to_json(tmp_path: Path, args: list) -> list:
    out = tmp_path / "out.json"
    rc = main(args + ["--report", "json", "--out", str(out)])
    assert rc in (0, 1), f"unexpected rc={rc}"
    return json.loads(out.read_text())


def test_examples_directory_exists():
    assert EXAMPLES.is_dir()
    assert any(EXAMPLES.glob("*.yaml"))


def test_insecure_pod_finds_all_expected_critical_high(tmp_path: Path):
    findings = _scan_to_json(tmp_path, ["--manifests", str(EXAMPLES / "insecure-pod.yaml")])
    ids = {f["id"] for f in findings}
    expected = {
        "POD-PRIV", "POD-ROOT", "POD-PE", "POD-HOSTNS",
        "POD-CAPS", "POD-HOSTPATH", "POD-RWFS",
        "POD-NO-SECCOMP", "POD-NO-LIMITS", "POD-NO-APPARMOR",
        "POD-SATOKEN",
    }
    missing = expected - ids
    assert not missing, f"missing expected findings: {missing}"


def test_insecure_rbac_finds_anon_admin_and_wildcard(tmp_path: Path):
    findings = _scan_to_json(tmp_path, ["--manifests", str(EXAMPLES / "insecure-rbac.yaml")])
    ids = {f["id"] for f in findings}
    assert "RBAC-ANON" in ids
    assert "RBAC-CLUSTER-ADMIN" in ids
    assert "RBAC-WILDCARD" in ids
    assert "RBAC-ESCALATION-VERB" in ids


def test_insecure_network_finds_lb_and_no_tls(tmp_path: Path):
    findings = _scan_to_json(tmp_path, ["--manifests", str(EXAMPLES / "insecure-network.yaml")])
    ids = {f["id"] for f in findings}
    assert "NET-LB-OPEN" in ids
    assert "NET-INGRESS-NO-TLS" in ids


def test_full_examples_directory_compliance_enriched(tmp_path: Path):
    """Every finding in the example sweep should carry compliance metadata."""
    findings = _scan_to_json(tmp_path, ["--manifests", str(EXAMPLES)])
    assert findings, "expected non-empty findings from examples sweep"
    enriched = [f for f in findings if f["cis_controls"] or f["mitre_attack"] or f["cwe"]]
    # POLICY-NONE / PSS findings won't fire here (no namespaces/CRDs in examples)
    # but every Pod/RBAC/Network finding should be enriched.
    assert len(enriched) / len(findings) >= 0.9, (
        f"compliance enrichment coverage too low: {len(enriched)}/{len(findings)}"
    )


def test_fail_on_critical_with_examples_returns_1(tmp_path: Path):
    out = tmp_path / "out.json"
    rc = main([
        "--manifests", str(EXAMPLES),
        "--report", "json",
        "--out", str(out),
        "--fail-on", "critical",
    ])
    assert rc == 1


def test_min_severity_critical_filters_examples(tmp_path: Path):
    findings = _scan_to_json(
        tmp_path,
        ["--manifests", str(EXAMPLES), "--min-severity", "critical"],
    )
    assert findings
    assert all(f["severity"] == "critical" for f in findings)


@pytest.mark.parametrize("fmt,extension", [
    ("json", "json"),
    ("text", "txt"),
    ("html", "html"),
    ("sarif", "sarif"),
    ("junit", "xml"),
    ("csv", "csv"),
])
def test_every_format_emits_non_empty_against_examples(tmp_path: Path, fmt: str, extension: str):
    out = tmp_path / f"out.{extension}"
    rc = main([
        "--manifests", str(EXAMPLES),
        "--report", fmt,
        "--out", str(out),
    ])
    assert rc == 0
    content = out.read_text()
    assert content.strip(), f"{fmt} output was empty"
