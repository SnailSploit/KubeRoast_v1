import json

from kuberoast.reporting import sarif
from kuberoast.utils.findings import Finding


def _sample():
    return [
        Finding(
            id="POD-PRIV",
            title="Privileged container",
            description="Runs privileged.",
            severity="critical",
            category="Pod Security",
            namespace="default",
            resource="pod/web::nginx",
            remediation="Set privileged=false.",
            cis_controls=["CIS-K8s-5.2.1"],
            mitre_attack=["T1611"],
            cwe=["CWE-250"],
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        ),
        Finding(
            id="RBAC-CLUSTER-ADMIN",
            title="cluster-admin granted",
            description="Bad.",
            severity="critical",
            category="RBAC",
            cis_controls=["CIS-K8s-5.1.1"],
            mitre_attack=["T1078.004"],
        ),
    ]


def test_sarif_valid_json_and_schema():
    out = sarif.emit(_sample())
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "KubeRoast"


def test_sarif_includes_unique_rules():
    findings = _sample() + _sample()
    out = sarif.emit(findings)
    data = json.loads(out)
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))
    assert "POD-PRIV" in rule_ids
    assert "RBAC-CLUSTER-ADMIN" in rule_ids


def test_sarif_results_match_findings():
    out = sarif.emit(_sample())
    data = json.loads(out)
    results = data["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "POD-PRIV"
    assert results[0]["level"] == "error"  # critical -> error


def test_sarif_severity_levels():
    findings = [
        Finding(id="A", title="a", description="d", severity="critical"),
        Finding(id="B", title="b", description="d", severity="high"),
        Finding(id="C", title="c", description="d", severity="medium"),
        Finding(id="D", title="d", description="d", severity="low"),
        Finding(id="E", title="e", description="d", severity="info"),
    ]
    data = json.loads(sarif.emit(findings))
    levels = [r["level"] for r in data["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note", "note"]


def test_sarif_security_severity_score():
    out = sarif.emit(_sample())
    data = json.loads(out)
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"


def test_sarif_tags_include_compliance():
    out = sarif.emit(_sample())
    data = json.loads(out)
    rule = next(r for r in data["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "POD-PRIV")
    tags = rule["properties"]["tags"]
    assert "CIS-K8s-5.2.1" in tags
    assert "T1611" in tags
    assert "CWE-250" in tags


def test_sarif_empty_findings():
    out = sarif.emit([])
    data = json.loads(out)
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []
