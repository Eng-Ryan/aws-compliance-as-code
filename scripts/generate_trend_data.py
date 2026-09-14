#!/usr/bin/env python3
"""
Generate a consolidated trend_data.json from all snapshot files in reports/
so the dashboard can load compliance posture over time without needing a
backend server.

Usage:
    python scripts/generate_trend_data.py
    # Then open dashboard/plot.html in a browser
"""

import json
from pathlib import Path


def main():
    reports_dir = Path("reports")
    snapshots = []

    if not reports_dir.exists():
        print("⚠️  reports/ directory not found. Run a scan first.")
        return

    for snapshot_file in sorted(reports_dir.glob("*_snapshot.json")):
        with open(snapshot_file, "r") as f:
            snapshots.append(json.load(f))

    if not snapshots:
        print("⚠️  No snapshot files found in reports/. Run a scan first.")
        return

    trend_data = {"snapshots": snapshots}

    output_path = reports_dir / "trend_data.json"
    with open(output_path, "w") as f:
        json.dump(trend_data, f, indent=2)

    print(f"✅ Generated {output_path} with {len(snapshots)} snapshots.")
    print("   Open dashboard/plot.html in a browser to view the trend.")


if __name__ == "__main__":
    main()
