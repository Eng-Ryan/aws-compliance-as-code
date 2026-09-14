"""
Reporting layer: renders the HTML compliance report and persists a dated
JSON snapshot of the summary so compliance posture can be trended over
time (e.g. plotted as "compliance score over the last 90 days").
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from engine.models import CheckResult
from engine.runner import ComplianceRunner

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def render_html_report(
    results: list[CheckResult],
    run_id: str,
    frameworks: list[str],
    output_dir: Path,
) -> Path:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    summary = ComplianceRunner.summarize(results)
    html = template.render(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        frameworks=frameworks,
        summary=summary,
        results=[r.to_dict() for r in results],
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{run_id}_report.html"
    report_path.write_text(html)
    return report_path


def write_trend_snapshot(
    results: list[CheckResult],
    run_id: str,
    frameworks: list[str],
    output_dir: Path,
) -> Path:
    """
    Append-only, one-file-per-run JSON snapshot. A simple downstream script
    (or a small dashboard) can glob these files to plot compliance_score_pct
    over time per framework — no database required for a portfolio demo.
    """
    summary = ComplianceRunner.summarize(results)
    snapshot = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "frameworks": frameworks,
        **summary,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = output_dir / f"{run_id}_snapshot.json"
    with open(snapshot_path, "w") as f:
        json.dump(snapshot, f, indent=2)
    return snapshot_path
