"""HTML reporter: dark-themed, single-file, severity-aware report."""
from __future__ import annotations

import datetime
import html
from collections import Counter
from typing import List

from .. import __version__
from ..utils.findings import Finding

CSS = """
:root{
  --bg:#0a0c10; --bg2:#0f1218; --card:#13161e; --text:#eef1f5; --muted:#9aa3b2;
  --border:rgba(255,255,255,.06); --accent:#a78bfa; --link:#7dd3fc;
  --crit:#ff4d6d; --high:#ff8a4c; --med:#ffc857; --low:#5eb3ff; --info:#a0a7b3;
}
*{box-sizing:border-box;}
body{
  margin:0; padding:0; background:linear-gradient(180deg,var(--bg),var(--bg2));
  color:var(--text); font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;
  line-height:1.55; min-height:100vh;
}
.wrap{max-width:1200px; margin:0 auto; padding:40px 28px 80px;}
header{display:flex; align-items:flex-end; justify-content:space-between; gap:24px; flex-wrap:wrap; margin-bottom:24px;}
.brand{display:flex; align-items:center; gap:14px;}
.logo{
  width:44px; height:44px; border-radius:12px; flex-shrink:0;
  background:conic-gradient(from 220deg,#a78bfa,#ff4d6d,#ffc857,#a78bfa);
  display:grid; place-items:center; font-weight:900; color:#0a0c10; font-size:1.1rem;
  box-shadow:0 6px 20px rgba(167,139,250,.25);
}
h1{margin:0; font-size:1.6rem; letter-spacing:-.02em;}
.tag{color:var(--muted); font-size:.92rem; margin-top:2px;}
.meta{color:var(--muted); font-size:.85rem; text-align:right;}
.bar{
  display:flex; height:6px; border-radius:999px; overflow:hidden;
  background:rgba(255,255,255,.04); margin:18px 0 24px;
}
.bar > span{display:block; height:100%;}
.bar .crit{background:var(--crit);}
.bar .high{background:var(--high);}
.bar .med{background:var(--med);}
.bar .low{background:var(--low);}
.bar .info{background:var(--info);}
.summary{display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:24px;}
.stat{
  background:var(--card); padding:14px 16px; border-radius:14px; border:1px solid var(--border);
  position:relative; overflow:hidden;
}
.stat::before{
  content:""; position:absolute; left:0; top:0; bottom:0; width:3px; opacity:.85;
}
.stat.total::before{background:var(--accent);}
.stat.critical::before{background:var(--crit);}
.stat.high::before{background:var(--high);}
.stat.medium::before{background:var(--med);}
.stat.low::before{background:var(--low);}
.stat.info::before{background:var(--info);}
.stat .label{color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.08em;}
.stat .value{font-size:1.7rem; font-weight:800; margin-top:2px; letter-spacing:-.02em;}
table{
  width:100%; border-collapse:separate; border-spacing:0;
  background:var(--card); border-radius:16px; overflow:hidden; border:1px solid var(--border);
}
thead th{
  text-align:left; font-weight:600; padding:14px 18px; border-bottom:1px solid var(--border);
  background:rgba(255,255,255,.02); font-size:.78rem; text-transform:uppercase; letter-spacing:.08em;
  color:var(--muted);
}
tbody td{vertical-align:top; padding:18px; border-top:1px solid rgba(255,255,255,.04);}
tbody tr:first-child td{border-top:none;}
tbody tr:hover{background:rgba(255,255,255,.02);}
.badge{
  display:inline-block; padding:.18rem .55rem; border-radius:999px; font-size:.7rem;
  font-weight:800; text-transform:uppercase; letter-spacing:.08em;
}
.badge.CRITICAL{background:var(--crit); color:#1a1a1a;}
.badge.HIGH{background:var(--high); color:#1a1a1a;}
.badge.MEDIUM{background:var(--med); color:#1a1a1a;}
.badge.LOW{background:var(--low); color:#1a1a1a;}
.badge.INFO{background:var(--info); color:#1a1a1a;}
.title{font-weight:700; color:var(--text);}
.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted); font-size:.78rem; margin-top:4px;}
.tag-chip{
  display:inline-block; padding:2px 8px; border-radius:6px;
  background:rgba(167,139,250,.10); color:var(--link); font-size:.72rem;
  font-family:ui-monospace,monospace; margin:2px 4px 2px 0; border:1px solid rgba(125,211,252,.18);
}
.meta-row{color:var(--muted); font-size:.85rem; margin-top:8px;}
.meta-row strong{color:#cbd5e1;}
.remediation{
  margin-top:8px; padding:10px 12px; border-radius:8px;
  background:rgba(94,179,255,.07); border:1px solid rgba(94,179,255,.18);
  font-size:.88rem;
}
.empty{padding:48px; text-align:center; color:var(--muted);}
footer{color:var(--muted); margin-top:24px; font-size:.82rem; text-align:center;}
footer a{color:var(--link); text-decoration:none;}
@media (max-width:640px){
  thead{display:none;}
  tbody td{display:block; padding:10px 18px;}
  tbody tr{display:block; padding:14px 0;}
}
"""


def _sev_badge(sev: str) -> str:
    s = (sev or "info").upper()
    return f"<span class='badge {html.escape(s)}'>{html.escape(s)}</span>"


def _tags(items: List[str]) -> str:
    return "".join(f"<span class='tag-chip'>{html.escape(i)}</span>" for i in items)


def _stat(label: str, value: int, css: str = "") -> str:
    return (
        f"<div class='stat {css}'>"
        f"<div class='label'>{html.escape(label)}</div>"
        f"<div class='value'>{value}</div></div>"
    )


def _bar(counts: Counter, total: int) -> str:
    if not total:
        return ""
    segments = []
    for sev_class, sev_key in [("crit", "critical"), ("high", "high"), ("med", "medium"), ("low", "low"), ("info", "info")]:
        n = counts.get(sev_key, 0)
        if not n:
            continue
        pct = (n / total) * 100
        segments.append(f"<span class='{sev_class}' style='width:{pct:.1f}%' title='{n} {sev_key}'></span>")
    return f"<div class='bar' role='img' aria-label='severity distribution'>{''.join(segments)}</div>"


def emit(findings: List[Finding], title: str = "KubeRoast Report") -> str:
    counts = Counter(f.severity for f in findings)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    summary_html = "".join([
        _stat("Total", len(findings), "total"),
        _stat("Critical", counts.get("critical", 0), "critical"),
        _stat("High", counts.get("high", 0), "high"),
        _stat("Medium", counts.get("medium", 0), "medium"),
        _stat("Low", counts.get("low", 0), "low"),
        _stat("Info", counts.get("info", 0), "info"),
    ])

    rows = []
    for f in findings:
        compliance: list = []
        if f.cis_controls:
            compliance.append("<div class='meta-row'><strong>CIS Kubernetes:</strong> " + _tags(f.cis_controls) + "</div>")
        if f.mitre_attack:
            compliance.append("<div class='meta-row'><strong>MITRE ATT&amp;CK:</strong> " + _tags(f.mitre_attack) + "</div>")
        if f.cwe:
            compliance.append("<div class='meta-row'><strong>CWE:</strong> " + _tags(f.cwe) + "</div>")
        if f.namespace:
            compliance.append(f"<div class='meta-row'><strong>Namespace:</strong> {html.escape(f.namespace)}</div>")
        rows.append(
            "<tr>"
            f"<td>{_sev_badge(f.severity)}</td>"
            f"<td><div class='title'>{html.escape(f.title or '')}</div>"
            f"<div class='id'>{html.escape(f.id)} &middot; {html.escape(f.category or '')}</div></td>"
            f"<td><code>{html.escape(f.resource or '-')}</code></td>"
            f"<td><div>{html.escape(f.description or '')}</div>"
            + (f"<div class='remediation'><strong>Remediation:</strong> {html.escape(f.remediation or '')}</div>"
               if f.remediation else "")
            + "".join(compliance)
            + "</td>"
            "</tr>"
        )

    body_table = (
        "<table><thead><tr>"
        "<th>Severity</th><th>Finding</th><th>Resource</th><th>Details</th>"
        "</tr></thead><tbody>"
        + ("".join(rows) if rows else
           "<tr><td colspan='4' class='empty'>No findings.</td></tr>")
        + "</tbody></table>"
    )

    page = (
        '<!doctype html><html lang="en">'
        '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{html.escape(title)}</title><style>{CSS}</style></head>'
        '<body><div class="wrap">'
        '<header>'
        '<div class="brand">'
        '<div class="logo">KR</div>'
        f'<div><h1>{html.escape(title)}</h1>'
        f'<div class="tag">Offensive Kubernetes misconfig &amp; attack-path scanner</div></div>'
        '</div>'
        f'<div class="meta">v{html.escape(__version__)}<br>{html.escape(now)}</div>'
        '</header>'
        + _bar(counts, len(findings))
        + f'<div class="summary">{summary_html}</div>'
        + body_table
        + f'<footer>Generated by <a href="https://github.com/SnailSploit/KubeRoast_v1">KubeRoast v{html.escape(__version__)}</a></footer>'
        '</div></body></html>'
    )
    return page
