"""JUnit XML output for CI test reporting (Jenkins, GitLab, CircleCI, etc.)."""
import html as _html
from collections import defaultdict
from typing import List
from xml.sax.saxutils import quoteattr

from ..utils.findings import Finding


def _escape(text: str) -> str:
    return _html.escape(text or "", quote=False)


def emit(findings: List[Finding]) -> str:
    """Group findings by category as test suites; each finding is a failed test case."""
    by_category: dict = defaultdict(list)
    for f in findings:
        by_category[f.category or "general"].append(f)

    total = len(findings)
    failures = sum(1 for f in findings if f.severity in ("critical", "high"))
    errors = sum(1 for f in findings if f.severity == "critical")

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        f'<testsuites name="kuberoast" tests="{total}" '
        f'failures="{failures}" errors="{errors}">'
    )

    for category, items in sorted(by_category.items()):
        cat_failures = sum(1 for f in items if f.severity in ("critical", "high"))
        cat_errors = sum(1 for f in items if f.severity == "critical")
        lines.append(
            f'  <testsuite name={quoteattr(category)} tests="{len(items)}" '
            f'failures="{cat_failures}" errors="{cat_errors}">'
        )
        for f in items:
            classname = quoteattr(f.category or "general")
            test_name = quoteattr(f"{f.id}: {f.title}")
            lines.append(f"    <testcase classname={classname} name={test_name}>")
            failure_message = quoteattr(f"[{f.severity.upper()}] {f.title}")
            failure_type = quoteattr(f.id)
            body = _escape(
                f"{f.description}\n"
                f"Resource: {f.resource or '-'}\n"
                f"Namespace: {f.namespace or '-'}\n"
                f"Remediation: {f.remediation or '-'}"
            )
            tag = "error" if f.severity == "critical" else "failure"
            lines.append(
                f"      <{tag} message={failure_message} type={failure_type}>{body}</{tag}>"
            )
            lines.append("    </testcase>")
        lines.append("  </testsuite>")

    lines.append("</testsuites>")
    return "\n".join(lines)
