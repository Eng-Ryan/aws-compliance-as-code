"""
CLI entrypoint for the compliance-as-code engine.

Usage:
    python main.py scan --frameworks soc2,nist800-53 --output reports/
    python main.py scan --frameworks soc2 --output reports/ --evidence-dir evidence/
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
import click

from engine.evidence import EvidenceCollector
from engine.loader import load_controls, resolve_all
from engine.report import load_trend_history, render_html_report, write_trend_snapshot
from engine.runner import ComplianceRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("compliance-engine")


@click.group()
def cli():
    """Compliance-as-code engine — SOC 2 / NIST 800-53 controls against live AWS."""


@cli.command()
@click.option(
    "--frameworks",
    default="soc2,nist800-53",
    help="Comma-separated framework names to run (must match `framework:` in controls/*.yaml).",
)
@click.option(
    "--controls-dir",
    default="controls",
    type=click.Path(path_type=Path),
    help="Directory containing control YAML files.",
)
@click.option(
    "--output",
    default="reports",
    type=click.Path(path_type=Path),
    help="Directory to write the HTML report and trend snapshot to.",
)
@click.option(
    "--evidence-dir",
    default="evidence",
    type=click.Path(path_type=Path),
    help="Directory to write hashed evidence records to.",
)
@click.option(
    "--evidence-bucket",
    default=None,
    help="Optional S3 bucket to also upload evidence records to.",
)
@click.option(
    "--profile",
    default=None,
    help="AWS named profile to use (defaults to standard boto3 credential resolution).",
)
def scan(frameworks, controls_dir, output, evidence_dir, evidence_bucket, profile):
    """Run all checks for the given frameworks against the target AWS account."""
    framework_list = [f.strip() for f in frameworks.split(",") if f.strip()]
    run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"

    logger.info("Starting scan %s for frameworks: %s", run_id, framework_list)

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    controls = load_controls(controls_dir, frameworks=framework_list)
    if not controls:
        logger.error("No controls loaded for frameworks %s — check controls-dir and framework names.", framework_list)
        raise click.ClickException("No controls loaded. Aborting.")
    logger.info("Loaded %d controls", len(controls))

    resolved = resolve_all(controls)

    runner = ComplianceRunner(session=session)
    results = runner.run(resolved)

    summary = ComplianceRunner.summarize(results)
    logger.info(
        "Scan complete: %d passed, %d failed, %d errored (%.1f%% compliant)",
        summary["passed"],
        summary["failed"],
        summary["errored"],
        summary["compliance_score_pct"],
    )

    evidence_collector = EvidenceCollector(evidence_dir, s3_bucket=evidence_bucket, session=session)
    manifest_path = evidence_collector.capture_all(results, run_id)
    logger.info("Evidence manifest written to %s", manifest_path)

    report_path = render_html_report(results, run_id, framework_list, output)
    logger.info("HTML report written to %s", report_path)

    snapshot_path = write_trend_snapshot(results, run_id, framework_list, output)
    logger.info("Trend snapshot written to %s", snapshot_path)

    click.echo(f"\nCompliance score: {summary['compliance_score_pct']}%")
    click.echo(f"Report:   {report_path}")
    click.echo(f"Evidence: {manifest_path}")


@cli.command()
@click.argument("control_id")
@click.option("--framework", required=True, help="Framework name (e.g. soc2, nist800-53)")
@click.option("--title", required=True, help="Control title")
@click.option("--description", required=True, help="Control description")
@click.option("--service", required=True, help="Primary AWS service (iam, s3, ec2, etc.)")
@click.option("--checks-dir", default="checks", type=click.Path(path_type=Path))
@click.option("--model", default="claude-sonnet-5", help="Anthropic model to use")
def draft_check(control_id, framework, title, description, service, checks_dir, model):
    """Use AI to draft a candidate check function for an unmapped control."""
    from engine.ai_mapper import draft_check_function, check_anthropic_available

    if not check_anthropic_available():
        raise click.ClickException(
            "Anthropic API not available. Install with: pip install anthropic\n"
            "Then set ANTHROPIC_API_KEY in your environment."
        )

    click.echo(f"Drafting check for {control_id} ({framework})...")
    result = draft_check_function(
        control_id=control_id,
        framework=framework,
        title=title,
        description=description,
        service=service,
        checks_dir=checks_dir,
        model=model,
    )

    if "error" in result:
        raise click.ClickException(result["error"])

    click.echo(f"\n{'='*60}")
    click.echo(f"Function: {result['function_name']}")
    click.echo(f"File:     {result['suggested_file']}")
    click.echo(f"Model:    {result['model_used']}")
    click.echo(f"{'='*60}\n")
    click.echo(result["source_code"])
    click.echo(f"\n{'='*60}")
    click.echo("⚠️  REVIEW REQUIRED: This is AI-generated code. Review before adding to checks/.")


@cli.command()
@click.option("--title", required=True, help="Control title to match")
@click.option("--description", required=True, help="Control description")
@click.option("--checks-dir", default="checks", type=click.Path(path_type=Path))
@click.option("--model", default="claude-sonnet-5", help="Anthropic model to use")
def map_control(title, description, checks_dir, model):
    """Use AI to suggest mapping a control to an existing check function."""
    from engine.ai_mapper import suggest_existing_mapping, check_anthropic_available

    if not check_anthropic_available():
        raise click.ClickException(
            "Anthropic API not available. Install with: pip install anthropic\n"
            "Then set ANTHROPIC_API_KEY in your environment."
        )

    click.echo("Analyzing control against existing checks...")
    result = suggest_existing_mapping(
        title=title,
        description=description,
        checks_dir=checks_dir,
        model=model,
    )

    if "error" in result:
        raise click.ClickException(result["error"])

    click.echo(f"\nMapping:    {result.get('mapped_function', 'No match found')}")
    click.echo(f"Confidence: {result.get('confidence', 'unknown')}")
    click.echo(f"Reasoning:  {result.get('reasoning', 'N/A')}")
    click.echo("\n⚠️  REVIEW REQUIRED: AI-suggested mapping needs human verification.")


@cli.command()
@click.option(
    "--snapshots-dir",
    default="reports",
    type=click.Path(path_type=Path),
    help="Directory containing trend snapshot JSON files.",
)
@click.option(
    "--limit",
    default=10,
    help="Number of most recent snapshots to display.",
)
def trends(snapshots_dir, limit):
    """Display compliance score trends over time from saved snapshots."""
    history = load_trend_history(snapshots_dir)

    if not history:
        click.echo(f"No trend snapshots found in {snapshots_dir}.")
        click.echo("Run 'python main.py scan' to generate snapshots.")
        return

    click.echo(f"\nCompliance Posture History (last {limit} runs):\n")
    click.echo(f"{'Run ID':<30} {'Date':<20} {'Score':<8} {'Pass':<6} {'Fail':<6} {'Error':<6}")
    click.echo("=" * 80)

    for snapshot in history[-limit:]:
        run_id = snapshot.get("run_id", "unknown")[:28]
        generated = snapshot.get("generated_at", "")[:19].replace("T", " ")
        score = snapshot.get("compliance_score_pct", 0.0)
        passed = snapshot.get("passed", 0)
        failed = snapshot.get("failed", 0)
        errored = snapshot.get("errored", 0)

        click.echo(f"{run_id:<30} {generated:<20} {score:>6.1f}%  {passed:<6} {failed:<6} {errored:<6}")

    # Summary stats
    if len(history) >= 2:
        first = history[0]
        last = history[-1]
        delta = last.get("compliance_score_pct", 0) - first.get("compliance_score_pct", 0)
        direction = "↑" if delta > 0 else "↓" if delta < 0 else "→"

        click.echo("=" * 80)
        click.echo(f"Total runs: {len(history)}")
        click.echo(f"Score change: {direction} {abs(delta):.1f}% (first → last)")


if __name__ == "__main__":
    cli()
