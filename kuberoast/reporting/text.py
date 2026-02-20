from collections import Counter
from typing import List
from ..utils.findings import Finding

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def emit(findings: List[Finding]) -> str:
    if not findings:
        return "No findings."

    lines: list[str] = []

    # Summary header
    counts = Counter(f.severity for f in findings)
    summary_parts = [f"{counts.get(s, 0)} {s}" for s in SEVERITY_ORDER if counts.get(s, 0)]
    lines.append(f"=== kuberoast scan: {len(findings)} findings ({', '.join(summary_parts)}) ===")
    lines.append("")

    # Group by severity, ordered critical -> info
    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines.append(f"--- {sev.upper()} ({len(group)}) ---")
        for f in group:
            lines.append(f"  [{f.severity.upper()}] {f.title}")
            lines.append(f"    Resource:    {f.resource or '-'}")
            lines.append(f"    Description: {f.description}")
            if f.remediation:
                lines.append(f"    Remediation: {f.remediation}")
            lines.append("")

    return "\n".join(lines)
