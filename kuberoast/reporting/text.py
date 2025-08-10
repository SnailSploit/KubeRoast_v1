from typing import List
from ..utils.findings import Finding

def emit(findings: List[Finding]) -> str:
    lines = []
    for f in findings:
        line = f"[{f.severity.upper()}] {f.title} :: {f.resource or '-'} :: {f.description}"
        lines.append(line)
    return "\n".join(lines)
