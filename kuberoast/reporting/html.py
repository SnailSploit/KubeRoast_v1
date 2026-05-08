import html
from collections import Counter
from typing import List

from .. import __version__
from ..utils.findings import Finding

CSS = """
:root{ --bg:#0b0d10; --card:#13161a; --text:#eef1f5; --muted:#a7b0bf; --border:rgba(255,255,255,.08);
       --crit:#ff5151; --high:#ff8a65; --med:#ffb84d; --low:#61c0ff; --info:#bdbdbd; }
*{ box-sizing:border-box; }
body{ margin:0; padding:32px; background:var(--bg); color:var(--text);
      font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial,sans-serif;
      line-height:1.5; }
header{ display:flex; align-items:center; justify-content:space-between; margin-bottom:24px; flex-wrap:wrap; gap:16px; }
h1{ font-size:1.8rem; margin:0; }
h1 small{ color:var(--muted); font-size:.9rem; font-weight:400; margin-left:8px; }
.summary{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }
.stat{ background:var(--card); padding:12px 18px; border-radius:12px; border:1px solid var(--border); min-width:100px; }
.stat .label{ color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }
.stat .value{ font-size:1.5rem; font-weight:700; margin-top:4px; }
.stat.critical .value{ color:var(--crit); }
.stat.high .value{ color:var(--high); }
.stat.medium .value{ color:var(--med); }
.stat.low .value{ color:var(--low); }
.stat.info .value{ color:var(--info); }
table{ width:100%; border-collapse:separate; border-spacing:0; background:var(--card);
       border-radius:14px; overflow:hidden; border:1px solid var(--border); }
thead th{ text-align:left; font-weight:600; padding:14px 16px; border-bottom:1px solid var(--border);
          background:rgba(255,255,255,.02); font-size:.85rem; text-transform:uppercase; letter-spacing:.05em; }
tbody td{ vertical-align:top; padding:14px 16px; border-top:1px solid rgba(255,255,255,.04); }
tbody tr:first-child td{ border-top:none; }
tbody tr:hover{ background:rgba(255,255,255,.02); }
.badge{ display:inline-block; padding:.15rem .55rem; border-radius:999px; font-size:.75rem; font-weight:700;
        text-transform:uppercase; letter-spacing:.05em; }
.badge.CRITICAL{ background:var(--crit); color:#1a1a1a; }
.badge.HIGH{ background:var(--high); color:#1a1a1a; }
.badge.MEDIUM{ background:var(--med); color:#1a1a1a; }
.badge.LOW{ background:var(--low); color:#1a1a1a; }
.badge.INFO{ background:var(--info); color:#1a1a1a; }
.tag{ display:inline-block; padding:2px 8px; border-radius:6px; background:rgba(255,255,255,.06);
      color:var(--muted); font-size:.72rem; font-family:monospace; margin:2px 4px 2px 0; }
.meta{ color:var(--muted); font-size:.85rem; margin-top:6px; }
.id{ font-family:monospace; color:var(--muted); font-size:.8rem; }
footer{ color:var(--muted); margin-top:24px; font-size:.85rem; text-align:center; }
"""


def _sev_badge(sev: str) -> str:
    s = (sev or "info").upper()
    return f"<span class='badge {html.escape(s)}'>{html.escape(s)}</span>"


def _tags(items: List[str]) -> str:
    return "".join(f"<span class='tag'>{html.escape(i)}</span>" for i in items)


def _stat(label: str, value: int, css_class: str = "") -> str:
    return (
        f"<div class='stat {css_class}'>"
        f"<div class='label'>{html.escape(label)}</div>"
        f"<div class='value'>{value}</div></div>"
    )


def emit(findings: List[Finding], title: str = "KubeRoast Report") -> str:
    counts = Counter(f.severity for f in findings)
    stats_html = "".join(
        [
            _stat("Total", len(findings)),
            _stat("Critical", counts.get("critical", 0), "critical"),
            _stat("High", counts.get("high", 0), "high"),
            _stat("Medium", counts.get("medium", 0), "medium"),
            _stat("Low", counts.get("low", 0), "low"),
            _stat("Info", counts.get("info", 0), "info"),
        ]
    )

    rows = []
    for f in findings:
        compliance = []
        if f.cis_controls:
            compliance.append("<div class='meta'><strong>CIS:</strong> " + _tags(f.cis_controls) + "</div>")
        if f.mitre_attack:
            compliance.append("<div class='meta'><strong>MITRE:</strong> " + _tags(f.mitre_attack) + "</div>")
        if f.cwe:
            compliance.append("<div class='meta'><strong>CWE:</strong> " + _tags(f.cwe) + "</div>")
        rows.append(
            "<tr>"
            f"<td>{_sev_badge(f.severity)}</td>"
            f"<td><div>{html.escape(f.title or '')}</div>"
            f"<div class='id'>{html.escape(f.id)} &middot; {html.escape(f.category or '')}</div></td>"
            f"<td>{html.escape(f.resource or '-')}</td>"
            f"<td><div>{html.escape(f.description or '')}</div>"
            + (f"<div class='meta'><strong>Remediation:</strong> {html.escape(f.remediation or '')}</div>"
               if f.remediation else "")
            + "".join(compliance)
            + "</td>"
            "</tr>"
        )

    body = (
        '<!doctype html><html lang="en">'
        '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{html.escape(title)}</title><style>{CSS}</style></head>'
        '<body>'
        '<header>'
        f'<h1>{html.escape(title)} <small>v{html.escape(__version__)}</small></h1>'
        '</header>'
        f'<div class="summary">{stats_html}</div>'
        '<table><thead><tr>'
        '<th>Severity</th><th>Finding</th><th>Resource</th><th>Details</th>'
        '</tr></thead><tbody>'
        + ("".join(rows) if rows else '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:32px;">No findings.</td></tr>') +
        '</tbody></table>'
        f'<footer>Generated by KubeRoast v{html.escape(__version__)}</footer>'
        '</body></html>'
    )
    return body
