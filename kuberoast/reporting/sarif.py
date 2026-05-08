"""SARIF v2.1.0 output for GitHub code scanning, Azure DevOps, and other tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
"""
import json
from typing import List

from .. import __version__
from ..utils.findings import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF level mapping (note: SARIF only has error/warning/note/none)
SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.0",
    "info": "0.0",
}


def _build_rules(findings: List[Finding]) -> List[dict]:
    """Build a unique set of SARIF rule objects from finding IDs."""
    seen: dict = {}
    for f in findings:
        if f.id in seen:
            continue
        rule = {
            "id": f.id,
            "name": f.id.replace("-", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "help": {
                "text": f.remediation or "See references for remediation guidance.",
                "markdown": _help_markdown(f),
            },
            "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(f.severity, "warning")},
            "properties": {
                "category": f.category,
                "security-severity": SEVERITY_TO_SCORE.get(f.severity, "5.0"),
                "tags": _build_tags(f),
            },
        }
        if f.references:
            rule["helpUri"] = f.references[0]
        seen[f.id] = rule
    return list(seen.values())


def _build_tags(f: Finding) -> List[str]:
    tags = ["security", f.category.lower().replace(" ", "-")]
    tags.extend(f.cis_controls)
    tags.extend(f.mitre_attack)
    tags.extend(f.cwe)
    return tags


def _help_markdown(f: Finding) -> str:
    parts = [f"**{f.title}**", "", f.description]
    if f.remediation:
        parts.extend(["", f"**Remediation:** {f.remediation}"])
    if f.cis_controls:
        parts.extend(["", f"**CIS Kubernetes Benchmark:** {', '.join(f.cis_controls)}"])
    if f.mitre_attack:
        parts.extend(["", f"**MITRE ATT&CK:** {', '.join(f.mitre_attack)}"])
    if f.cwe:
        parts.extend(["", f"**CWE:** {', '.join(f.cwe)}"])
    if f.references:
        parts.append("")
        parts.append("**References:**")
        for ref in f.references:
            parts.append(f"- {ref}")
    return "\n".join(parts)


def _build_result(f: Finding) -> dict:
    location_uri = f.resource or "cluster"
    if f.namespace and f.resource:
        location_uri = f"{f.namespace}/{f.resource}"
    result = {
        "ruleId": f.id,
        "level": SEVERITY_TO_LEVEL.get(f.severity, "warning"),
        "message": {"text": f.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location_uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "severity": f.severity,
            "category": f.category,
            "namespace": f.namespace or "",
            "kuberoast-id": f.id,
        },
    }
    if f.metadata:
        result["properties"].update(f.metadata)
    return result


def emit(findings: List[Finding]) -> str:
    rules = _build_rules(findings)
    results = [_build_result(f) for f in findings]

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "KubeRoast",
                        "version": __version__,
                        "informationUri": "https://github.com/SnailSploit/KubeRoast_v1",
                        "rules": rules,
                        "shortDescription": {
                            "text": "Offensive Kubernetes misconfiguration & attack-path scanner"
                        },
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }
    return json.dumps(sarif, indent=2)
