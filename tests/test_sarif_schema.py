"""Validate KubeRoast SARIF output against the official OASIS v2.1.0 schema.

Uses a locally-cached copy of the SARIF JSON schema so tests don't hit the
network. If the schema bundle is missing or jsonschema is unavailable, the
test is skipped — but in the standard dev install (`pip install -e .[dev]`)
we add jsonschema and ship the schema file, so it always runs.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kuberoast.reporting import sarif as sarif_report
from kuberoast.utils.findings import Finding

jsonschema = pytest.importorskip("jsonschema")

SARIF_SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-2.1.0-schema.json"


@pytest.fixture(scope="module")
def sarif_schema() -> dict:
    if not SARIF_SCHEMA_PATH.exists():
        pytest.skip(f"SARIF schema not bundled at {SARIF_SCHEMA_PATH}")
    return json.loads(SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))


def _findings():
    return [
        Finding(
            id="POD-PRIV",
            title="Privileged container",
            description="Bad",
            severity="critical",
            category="Pod Security",
            namespace="prod",
            resource="pod/web-0::nginx",
            remediation="Don't be privileged",
            cis_controls=["CIS-K8s-5.2.1"],
            mitre_attack=["T1611"],
            cwe=["CWE-250"],
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        ),
        Finding(
            id="RBAC-CLUSTER-ADMIN",
            title="cluster-admin granted",
            description="Bad",
            severity="critical",
            category="RBAC",
            cis_controls=["CIS-K8s-5.1.1"],
            mitre_attack=["T1078.004"],
        ),
        Finding(
            id="NET-LB-OPEN",
            title="LB open",
            description="Bad",
            severity="high",
            category="Network",
            namespace="prod",
            resource="service/web",
        ),
    ]


def test_sarif_validates_against_official_schema(sarif_schema):
    out = sarif_report.emit(_findings())
    data = json.loads(out)
    jsonschema.validate(instance=data, schema=sarif_schema)


def test_empty_sarif_validates(sarif_schema):
    out = sarif_report.emit([])
    data = json.loads(out)
    jsonschema.validate(instance=data, schema=sarif_schema)


def test_single_finding_sarif_validates(sarif_schema):
    out = sarif_report.emit([_findings()[0]])
    data = json.loads(out)
    jsonschema.validate(instance=data, schema=sarif_schema)


def test_sarif_run_has_tool_driver_required_fields():
    """Even without schema validation, sanity-check the SARIF shape."""
    data = json.loads(sarif_report.emit(_findings()))
    run = data["runs"][0]
    driver = run["tool"]["driver"]
    assert "name" in driver
    assert "version" in driver
    assert "rules" in driver


def test_sarif_results_have_required_fields():
    data = json.loads(sarif_report.emit(_findings()))
    for result in data["runs"][0]["results"]:
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "text" in result["message"]
        assert "locations" in result and len(result["locations"]) >= 1
