"""
reporting.py
------------
Turns a list of RuleResult into console output, CSV, and a self-contained
HTML report.
"""

from __future__ import annotations

import csv
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import List

try:
    from .rules import RuleResult, Status
except ImportError:
    from rules import RuleResult, Status

_STATUS_COLORS = {
    Status.PASS: "#1a7f37",
    Status.FAIL: "#c0392b",
    Status.WARN: "#b7791f",
    Status.ERROR: "#6b7280",
    Status.NOT_APPLICABLE: "#6b7280",
}


def print_console_report(results: List[RuleResult], target: str) -> None:
    width = 100
    print("=" * width)
    print(f"FortiGate CIS Benchmark Compliance Check - {target}")
    print(f"Generated: {datetime.now(timezone.utc).isoformat()}Z")
    print("=" * width)

    counts = {s: 0 for s in Status}
    for r in results:
        counts[r.status] += 1
        marker = {
            Status.PASS: "[PASS]",
            Status.FAIL: "[FAIL]",
            Status.WARN: "[WARN]",
            Status.ERROR: "[ERR ]",
            Status.NOT_APPLICABLE: "[ N/A]",
        }[r.status]
        print(f"{marker} {r.rule_id:<6} L{r.level}  {r.title}")
        print(f"        expected: {r.expected}")
        print(f"        actual  : {r.actual}")
        if r.status in (Status.FAIL, Status.WARN):
            print(f"        fix     : {r.remediation.splitlines()[0]} ...")
        print("-" * width)

    total = len(results)
    scored = counts[Status.PASS] + counts[Status.FAIL] + counts[Status.WARN]
    pct = (counts[Status.PASS] / scored * 100) if scored else 0.0
    print(
        f"Summary: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
        f"{counts[Status.WARN]} WARN, {counts[Status.ERROR]} ERROR "
        f"out of {total} checks  |  Compliance score: {pct:.1f}%"
    )
    print("=" * width)


def write_csv_report(results: List[RuleResult], out_path: str) -> None:
    path = Path(out_path)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["rule_id", "level", "title", "status", "expected", "actual", "remediation"]
        )
        for r in results:
            writer.writerow(
                [r.rule_id, r.level, r.title, r.status.value, r.expected, r.actual, r.remediation]
            )


def write_html_report(results: List[RuleResult], out_path: str, target: str) -> None:
    counts = {s: 0 for s in Status}
    for r in results:
        counts[r.status] += 1
    scored = counts[Status.PASS] + counts[Status.FAIL] + counts[Status.WARN]
    pct = (counts[Status.PASS] / scored * 100) if scored else 0.0

    rows_html = []
    for r in results:
        color = _STATUS_COLORS[r.status]
        rows_html.append(
            f"""
            <tr>
              <td>{html.escape(r.rule_id)}</td>
              <td>{r.level}</td>
              <td>{html.escape(r.title)}</td>
              <td><span class="badge" style="background:{color}">{r.status.value}</span></td>
              <td>{html.escape(r.expected)}</td>
              <td>{html.escape(r.actual)}</td>
              <td><pre>{html.escape(r.remediation)}</pre></td>
            </tr>
            """
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FortiGate CIS Benchmark Report - {html.escape(target)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1f2328; background: #f6f8fa; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #57606a; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
  .card {{ background: white; border: 1px solid #d0d7de; border-radius: 8px; padding: 1rem 1.5rem; }}
  .card .num {{ font-size: 1.8rem; font-weight: 700; }}
  table {{ border-collapse: collapse; width: 100%; background: white; border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #eaeef2; vertical-align: top; font-size: 0.9rem; }}
  th {{ background: #f0f3f6; }}
  .badge {{ color: white; padding: 0.15rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  pre {{ white-space: pre-wrap; margin: 0; font-size: 0.8rem; background: #f6f8fa; padding: 0.4rem; border-radius: 4px; }}
</style>
</head>
<body>
  <h1>FortiGate CIS Benchmark Compliance Report</h1>
  <div class="meta">Target: {html.escape(target)} &middot; Generated: {datetime.now(timezone.utc).isoformat()}Z</div>

  <div class="summary">
    <div class="card"><div class="num" style="color:{_STATUS_COLORS[Status.PASS]}">{counts[Status.PASS]}</div>PASS</div>
    <div class="card"><div class="num" style="color:{_STATUS_COLORS[Status.FAIL]}">{counts[Status.FAIL]}</div>FAIL</div>
    <div class="card"><div class="num" style="color:{_STATUS_COLORS[Status.WARN]}">{counts[Status.WARN]}</div>WARN</div>
    <div class="card"><div class="num" style="color:{_STATUS_COLORS[Status.ERROR]}">{counts[Status.ERROR]}</div>ERROR</div>
    <div class="card"><div class="num">{pct:.1f}%</div>Compliance score</div>
  </div>

  <table>
    <thead>
      <tr><th>ID</th><th>Level</th><th>Title</th><th>Status</th><th>Expected</th><th>Actual</th><th>Remediation</th></tr>
    </thead>
    <tbody>
      {''.join(rows_html)}
    </tbody>
  </table>
</body>
</html>
"""
    Path(out_path).write_text(doc, encoding="utf-8")
