"""Report generation from campaign metrics."""

from __future__ import annotations

import csv
import json
from typing import Any, Dict, List

from ..storage.store import Store


def campaign_summary(store: Store, campaign_id: int) -> Dict[str, Any]:
    stats = store.campaign_stats(campaign_id)
    delivered = stats["delivered"] or 0
    pct = lambda n: round((n / delivered) * 100, 1) if delivered else 0.0
    return {
        **stats,
        "open_rate_pct": pct(stats["opened"]),
        "click_rate_pct": pct(stats["clicked"]),
        "submit_rate_pct": pct(stats["submitted"]),
        "report_rate_pct": pct(stats["reported"]),
        "department_breakdown": store.department_breakdown(campaign_id),
    }


def _format_pct(value: float) -> str:
    return f"{value:.1f}%"


def to_text(summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append(f"Campaign #{summary['campaign_id']} report")
    lines.append("=" * 42)
    lines.append(f"  Delivered : {summary['delivered']}")
    lines.append(f"  Opened    : {summary['opened']} ({_format_pct(summary['open_rate_pct'])})")
    lines.append(f"  Clicked   : {summary['clicked']} ({_format_pct(summary['click_rate_pct'])})")
    lines.append(f"  Submitted : {summary['submitted']} ({_format_pct(summary['submit_rate_pct'])})")
    lines.append(f"  Reported  : {summary['reported']} ({_format_pct(summary['report_rate_pct'])})")

    breakdown = summary.get("department_breakdown") or []
    if breakdown:
        lines.append("")
        lines.append("By department")
        lines.append("-------------")
        header = f"{'Department':<20}{'Deliv':>7}{'Open':>7}{'Click':>7}{'Submit':>8}{'Report':>8}"
        lines.append(header)
        for row in breakdown:
            lines.append(
                f"{row['department'] or '(none)':<20}"
                f"{row['delivered']:>7}{row['opened']:>7}{row['clicked']:>7}"
                f"{row['submitted']:>8}{row['reported']:>8}"
            )
    return "\n".join(lines)


def to_json(summary: Dict[str, Any]) -> str:
    return json.dumps(summary, indent=2)


def to_csv(summary: Dict[str, Any]) -> str:
    output = []
    buf: List[str] = []
    writer = csv.writer(buf)
    writer.writerow(["department", "delivered", "opened", "clicked", "submitted", "reported"])
    for row in summary.get("department_breakdown") or []:
        writer.writerow([
            row["department"] or "(none)",
            row["delivered"], row["opened"], row["clicked"],
            row["submitted"], row["reported"],
        ])
    output.append("\n".join(buf))
    return "\n".join(output)


def to_html(summary: Dict[str, Any]) -> str:
    rows = ""
    for row in summary.get("department_breakdown") or []:
        rows += (
            f"<tr><td>{row['department'] or '(none)'}</td>"
            f"<td>{row['delivered']}</td><td>{row['opened']}</td>"
            f"<td>{row['clicked']}</td><td>{row['submitted']}</td>"
            f"<td>{row['reported']}</td></tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>PhishGuard report #{summary['campaign_id']}</title>
<style>
body{{font-family:-apple-system,"Segoe UI",Roboto,sans-serif;margin:40px;color:#111}}
table{{border-collapse:collapse;margin-top:16px}}
th,td{{border:1px solid #ddd;padding:8px 14px;text-align:right}}
th:first-child,td:first-child{{text-align:left}}
th{{background:#f3f4f6}}
.kpi{{display:inline-block;margin:8px 24px 8px 0}}
.kpi b{{font-size:22px;display:block}}
</style></head><body>
<h1>PhishGuard campaign #{summary['campaign_id']}</h1>
<div>
<span class="kpi"><b>{summary['delivered']}</b>Delivered</span>
<span class="kpi"><b>{_format_pct(summary['open_rate_pct'])}</b>Opened</span>
<span class="kpi"><b>{_format_pct(summary['click_rate_pct'])}</b>Clicked</span>
<span class="kpi"><b>{_format_pct(summary['submit_rate_pct'])}</b>Submitted</span>
<span class="kpi"><b>{_format_pct(summary['report_rate_pct'])}</b>Reported</span>
</div>
<table>
<tr><th>Department</th><th>Delivered</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th>Reported</th></tr>
{rows}
</table>
</body></html>"""
