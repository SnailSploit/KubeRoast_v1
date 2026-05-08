from collections import Counter
from typing import List

from ..utils.findings import Finding

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def emit(findings: List[Finding]) -> str:
    if not findings:
        return "No findings."

    lines: list = []

    counts = Counter(f.severity for f in findings)
    summary_parts = [f"{counts.get(s, 0)} {s}" for s in SEVERITY_ORDER if counts.get(s, 0)]
    lines.append(f"=== kuberoast scan: {len(findings)} findings ({', '.join(summary_parts)}) ===")
    lines.append("")

    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines.append(f"--- {sev.upper()} ({len(group)}) ---")
        for f in group:
            lines.append(f"  [{f.severity.upper()}] {f.title} ({f.id})")
            lines.append(f"    Resource:    {f.resource or '-'}")
            if f.namespace:
                lines.append(f"    Namespace:   {f.namespace}")
            lines.append(f"    Description: {f.description}")
            if f.remediation:
                lines.append(f"    Remediation: {f.remediation}")
            if f.cis_controls:
                lines.append(f"    CIS:         {', '.join(f.cis_controls)}")
            if f.mitre_attack:
                lines.append(f"    MITRE:       {', '.join(f.mitre_attack)}")
            if f.cwe:
                lines.append(f"    CWE:         {', '.join(f.cwe)}")
            lines.append("")

    return "\n".join(lines)
