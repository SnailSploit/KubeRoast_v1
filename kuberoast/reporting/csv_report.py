"""CSV output for spreadsheets and analytics."""
import csv
import io
from typing import List

from ..utils.findings import Finding

COLUMNS = [
    "id",
    "severity",
    "title",
    "category",
    "namespace",
    "resource",
    "description",
    "remediation",
    "cis_controls",
    "mitre_attack",
    "cwe",
    "references",
]


def emit(findings: List[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(COLUMNS)
    for f in findings:
        writer.writerow(
            [
                f.id,
                f.severity,
                f.title,
                f.category,
                f.namespace or "",
                f.resource or "",
                f.description,
                f.remediation or "",
                ";".join(f.cis_controls),
                ";".join(f.mitre_attack),
                ";".join(f.cwe),
                ";".join(f.references),
            ]
        )
    return buf.getvalue()
