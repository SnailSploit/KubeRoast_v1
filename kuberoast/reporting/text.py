"""Text reporter: severity-grouped, color-aware human-readable output."""
from __future__ import annotations

import sys
from collections import Counter
from typing import IO, List, Optional

from ..utils.findings import Finding
from ..utils.style import (
    SEVERITY_COLOR,
    _colors_enabled,
    color,
    severity_badge,
)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_GLYPHS = {
    "critical": "✖",
    "high": "▲",
    "medium": "●",
    "low": "○",
    "info": "·",
}


def _rule(stream: Optional[IO]) -> str:
    return color("─" * 72, "gray", stream=stream)


def _summary(counts: Counter, total: int, stream: Optional[IO]) -> str:
    """One-line summary of counts by severity, e.g.
    'Found 12 issues — 3 critical · 4 high · 5 medium'."""
    parts = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        parts.append(color(f"{n} {sev}", SEVERITY_COLOR[sev], bold=True, stream=stream))
    detail = color(" · ", "gray", stream=stream).join(parts) if parts else "no findings"
    headline = color(f"Found {total} issue{'s' if total != 1 else ''}", "white", bold=True, stream=stream)
    arrow = color("—", "gray", stream=stream)
    return f"{headline} {arrow} {detail}"


def emit(findings: List[Finding], *, stream: Optional[IO] = None) -> str:
    """Render findings as text. Colors auto-enable on TTYs; opt out via NO_COLOR."""
    target = stream if stream is not None else sys.stdout

    if not findings:
        glyph = color("✓", "green", bold=True, stream=target)
        return f"{glyph} {color('No findings.', 'green', stream=target)}\n"

    counts = Counter(f.severity for f in findings)
    lines: list = []

    title = color("KubeRoast scan results", "magenta", bold=True, stream=target)
    lines.append(title)
    lines.append(_rule(target))
    lines.append(_summary(counts, len(findings), target))
    lines.append("")

    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        glyph = SEVERITY_GLYPHS[sev]
        header = color(
            f"{glyph} {sev.upper()} ({len(group)})",
            SEVERITY_COLOR[sev],
            bold=True,
            stream=target,
        )
        lines.append(header)
        lines.append(color("─" * (len(sev) + 8), "gray", stream=target))
        for f in group:
            badge = severity_badge(f.severity, stream=target)
            title_part = color(f.title, "white", bold=True, stream=target)
            id_part = color(f"({f.id})", "gray", stream=target)
            lines.append(f"  {badge} {title_part} {id_part}")
            _line(lines, "Resource",    f.resource or "-",        target)
            if f.namespace:
                _line(lines, "Namespace", f.namespace,             target)
            _line(lines, "Description", f.description,             target)
            if f.remediation:
                _line(lines, "Remediation", f.remediation,         target, value_color="green")
            if f.cis_controls:
                _line(lines, "CIS",        ", ".join(f.cis_controls),     target, value_color="cyan")
            if f.mitre_attack:
                _line(lines, "MITRE",      ", ".join(f.mitre_attack),     target, value_color="cyan")
            if f.cwe:
                _line(lines, "CWE",        ", ".join(f.cwe),              target, value_color="cyan")
            lines.append("")

    return "\n".join(lines)


def _line(
    lines: list,
    label: str,
    value: str,
    stream: Optional[IO],
    *,
    value_color: Optional[str] = None,
) -> None:
    label_str = color(f"{label:<11}", "gray", stream=stream)
    value_str = color(value, value_color, stream=stream) if value_color else value
    # When colors are disabled, indentation alignment still holds.
    if not _colors_enabled(stream):
        label_str = f"{label:<11}"
    lines.append(f"    {label_str} {value_str}")
