"""Render analysis results as a console table, JSON, CSV, standalone HTML, or IOC exports."""

from __future__ import annotations

import csv
import html
import io
import json
from collections.abc import Sequence
from datetime import datetime, timezone

from . import iocs
from .results import AnalysisResult

FORMATS = ["table", "json", "csv", "html", "iocs", "stix"]

COLUMNS = ["submission_id", "target", "verdict", "max_severity", "alerts", "malware"]


def _row(r: AnalysisResult) -> dict[str, str]:
    return {
        "submission_id": r.submission_id,
        "target": r.target,
        "verdict": r.verdict + (" (cached)" if r.cached_from else ""),
        "max_severity": r.max_severity or "-",
        "alerts": str(len(r.alerts)),
        "malware": ", ".join(r.malware_names) or "-",
    }


def to_table(results: Sequence[AnalysisResult]) -> str:
    rows = [_row(r) for r in results]
    widths = {c: max([len(c)] + [len(row[c]) for row in rows]) for c in COLUMNS}
    widths["target"] = min(widths["target"], 50)
    widths["malware"] = min(widths["malware"], 60)

    def cell(col: str, value: str) -> str:
        width = widths[col]
        if len(value) > width:
            # Keep the end of paths (the file name), the start of everything else.
            value = "…" + value[-(width - 1) :] if col == "target" else value[: width - 1] + "…"
        return value.ljust(width)

    def fmt(values: dict[str, str]) -> str:
        return "  ".join(cell(c, values[c]) for c in COLUMNS)

    lines = [fmt({c: c.upper() for c in COLUMNS}), "  ".join("-" * widths[c] for c in COLUMNS)]
    lines += [fmt(row) for row in rows]
    return "\n".join(lines)


def to_json(results: Sequence[AnalysisResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False)


def to_csv(results: Sequence[AnalysisResult]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS)
    writer.writeheader()
    for r in results:
        writer.writerow(_row(r))
    return buf.getvalue()


_VERDICT_CLASS = {"malicious": "bad", "suspicious": "warn", "no-detection": "ok"}


def to_html(results: Sequence[AnalysisResult], title: str = "IVX analysis report") -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    summary = (
        " · ".join(f"{html.escape(k)}: {v}" for k, v in sorted(counts.items())) or "no results"
    )

    body_rows = []
    for r in results:
        row = _row(r)
        cls = _VERDICT_CLASS.get(r.verdict, "")
        details = "".join(
            f"<li>{html.escape(a.name or a.id)} ({html.escape(a.severity or '-')})"
            + "".join(
                f"<br><code>{html.escape(m.name)}</code> md5={html.escape(m.md5 or '-')} "
                f"sha256={html.escape(m.sha256 or '-')}"
                for m in a.malware
            )
            + "</li>"
            for a in r.alerts
        )
        body_rows.append(
            "<tr>"
            f"<td>{html.escape(row['submission_id'])}</td>"
            f"<td>{html.escape(row['target'])}</td>"
            f"<td><span class='v {cls}'>{html.escape(row['verdict'])}</span></td>"
            f"<td>{html.escape(row['max_severity'])}</td>"
            f"<td>{html.escape(row['alerts'])}"
            + (f"<ul>{details}</ul>" if details else "")
            + "</td></tr>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ --bg:#fff; --fg:#1d2330; --muted:#667085; --line:#e4e7ec;
  --bad:#b42318; --warn:#b54708; --ok:#067647; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#11151c; --fg:#e6e9ef; --muted:#98a2b3;
  --line:#2a303b; --bad:#f97066; --warn:#fdb022; --ok:#47cd89; }} }}
body {{ background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,sans-serif;
  margin:0 auto; max-width:1100px; padding:24px 16px; }}
h1 {{ font-size:20px; margin:0 0 4px; }} .meta {{ color:var(--muted); margin-bottom:16px; }}
table {{ border-collapse:collapse; width:100%; }}
th,td {{ border-bottom:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; }}
th {{ font-size:12px; text-transform:uppercase; color:var(--muted); }}
td:nth-child(2) {{ word-break:break-all; }} ul {{ margin:6px 0 0; padding-left:18px; }}
.v {{ font-weight:600; }} .bad {{ color:var(--bad); }} .warn {{ color:var(--warn); }}
.ok {{ color:var(--ok); }} code {{ font-size:12px; }}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="meta">Generated {generated} by ivx-toolkit · {summary}</div>
<table><thead><tr><th>Submission</th><th>Target</th><th>Verdict</th><th>Severity</th>
<th>Alerts</th></tr></thead><tbody>
{"".join(body_rows)}
</tbody></table></body></html>
"""


def render(results: Sequence[AnalysisResult], fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return to_json(results)
    if fmt == "csv":
        return to_csv(results)
    if fmt == "html":
        return to_html(results)
    if fmt == "iocs":
        return iocs.to_csv(results)
    if fmt == "stix":
        return iocs.to_stix(results)
    return to_table(results)
