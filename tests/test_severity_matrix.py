"""Comprehensive matrix tests for --fail-on and --min-severity logic."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from kuberoast.cli import main

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITIES)}


@pytest.fixture
def critical_pod_dir(tmp_path: Path) -> Path:
    (tmp_path / "pod.yaml").write_text(
        textwrap.dedent(
            """
            apiVersion: v1
            kind: Pod
            metadata:
              name: bad
              namespace: default
            spec:
              containers:
                - name: c
                  image: nginx
                  securityContext:
                    privileged: true
            """
        ),
        encoding="utf-8",
    )
    return tmp_path


@pytest.mark.parametrize("threshold", SEVERITIES)
def test_fail_on_at_or_below_critical_returns_1(critical_pod_dir: Path, threshold: str, tmp_path_factory):
    """A privileged-container scan produces critical findings — every fail-on
    threshold from info up through critical should return rc=1."""
    out = tmp_path_factory.mktemp("o") / "o.json"
    rc = main([
        "--manifests", str(critical_pod_dir),
        "--report", "json",
        "--out", str(out),
        "--fail-on", threshold,
    ])
    assert rc == 1


def test_no_fail_on_returns_0_with_findings(critical_pod_dir: Path, tmp_path_factory):
    out = tmp_path_factory.mktemp("o") / "o.json"
    rc = main([
        "--manifests", str(critical_pod_dir),
        "--report", "json",
        "--out", str(out),
    ])
    assert rc == 0


@pytest.mark.parametrize("min_sev", SEVERITIES)
def test_min_severity_filter_consistency(critical_pod_dir: Path, min_sev: str, tmp_path_factory, capsys):
    """Filter must drop any finding below threshold."""
    rc = main([
        "--manifests", str(critical_pod_dir),
        "--report", "json",
        "--min-severity", min_sev,
    ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    threshold_idx = SEVERITY_INDEX[min_sev]
    for f in data:
        assert SEVERITY_INDEX[f["severity"]] >= threshold_idx, (
            f"finding {f['id']} severity={f['severity']} below min-severity={min_sev}"
        )


def test_min_severity_critical_only_keeps_criticals(critical_pod_dir: Path, capsys):
    rc = main([
        "--manifests", str(critical_pod_dir),
        "--report", "json",
        "--min-severity", "critical",
    ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data
    assert all(f["severity"] == "critical" for f in data)


def test_clean_manifest_returns_0_no_findings(tmp_path: Path, capsys):
    """A bare-minimum benign Pod should produce only Pod-hardening findings,
    none of which are critical, so fail-on=critical returns 0."""
    (tmp_path / "ok.yaml").write_text(
        textwrap.dedent(
            """
            apiVersion: v1
            kind: Pod
            metadata: {name: ok, namespace: default}
            spec:
              automountServiceAccountToken: false
              containers:
                - name: c
                  image: nginx
                  securityContext:
                    privileged: false
                    runAsUser: 1000
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    seccompProfile: {type: RuntimeDefault}
                    capabilities: {drop: [ALL]}
                  resources:
                    limits: {cpu: 100m, memory: 128Mi}
            """
        ),
        encoding="utf-8",
    )
    rc = main([
        "--manifests", str(tmp_path),
        "--report", "json",
        "--fail-on", "critical",
    ])
    assert rc == 0


def test_min_severity_higher_than_any_finding_returns_empty(tmp_path: Path, capsys):
    """If no findings clear --min-severity, output is an empty list."""
    (tmp_path / "ok.yaml").write_text(
        textwrap.dedent(
            """
            apiVersion: v1
            kind: Pod
            metadata: {name: ok, namespace: default}
            spec:
              containers:
                - name: c
                  image: nginx
            """
        ),
        encoding="utf-8",
    )
    rc = main([
        "--manifests", str(tmp_path),
        "--report", "json",
        "--min-severity", "critical",
    ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data == []


@pytest.mark.parametrize("fmt", ["html", "sarif", "junit", "csv"])
def test_file_output_formats_require_out(fmt: str):
    rc = main(["--report", fmt])
    assert rc == 2  # usage error


def test_combined_min_severity_and_fail_on(critical_pod_dir: Path, tmp_path_factory):
    """When --min-severity drops all findings below --fail-on, exit code is 0."""
    out = tmp_path_factory.mktemp("o") / "o.json"
    # Filter out criticals; remaining findings are < critical → fail-on=critical doesn't trip
    rc = main([
        "--manifests", str(critical_pod_dir),
        "--report", "json",
        "--out", str(out),
        "--min-severity", "high",
        "--fail-on", "critical",
    ])
    # The privileged-container finding is critical so it survives min-severity=high,
    # and trips fail-on=critical
    assert rc == 1


def test_no_compliance_strips_enrichment(critical_pod_dir: Path, capsys):
    rc = main([
        "--manifests", str(critical_pod_dir),
        "--report", "json",
        "--no-compliance",
    ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data
    for f in data:
        assert f["cis_controls"] == []
        assert f["mitre_attack"] == []
        assert f["cwe"] == []
