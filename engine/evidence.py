"""
Evidence collection layer.

For every check result, this module persists a timestamped, SHA-256-hashed
snapshot of the raw evidence dict the check produced. This is the pattern
platforms like Vanta/Drata use under the hood: the point isn't just "pass/
fail," it's having a defensible, tamper-evident record of *what was
actually observed* at the time of the check, which is what an auditor
actually wants to see.

Evidence is written locally by default (for demo purposes) but the
`upload_to_s3` flag mirrors how this would work against a real evidence
bucket in production — write once, hash, and never mutate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import boto3

from engine.models import CheckResult


class EvidenceCollector:
    def __init__(
        self,
        output_dir: Path,
        s3_bucket: Optional[str] = None,
        session: Optional[boto3.Session] = None,
    ):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.s3_bucket = s3_bucket
        self.session = session or boto3.Session()

    @staticmethod
    def _hash_payload(payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def capture(self, result: CheckResult, run_id: str) -> dict:
        """
        Persist a single evidence record and return its manifest entry
        (control ID, hash, and where it was stored).
        """
        timestamp = result.checked_at.strftime("%Y%m%dT%H%M%SZ")
        record = {
            "run_id": run_id,
            "control_id": result.control.control_id,
            "framework": result.control.framework,
            "status": result.status.value,
            "checked_at": result.checked_at.isoformat(),
            "evidence": result.evidence,
        }
        record["sha256"] = self._hash_payload(record["evidence"])

        filename = f"{run_id}_{result.control.control_id}_{timestamp}.json"
        local_path = self.output_dir / filename
        with open(local_path, "w") as f:
            json.dump(record, f, indent=2, default=str)

        storage_location = str(local_path)

        if self.s3_bucket:
            key = f"evidence/{run_id}/{filename}"
            self.session.client("s3").put_object(
                Bucket=self.s3_bucket,
                Key=key,
                Body=json.dumps(record, default=str).encode("utf-8"),
                ContentType="application/json",
            )
            storage_location = f"s3://{self.s3_bucket}/{key}"

        return {
            "control_id": result.control.control_id,
            "sha256": record["sha256"],
            "location": storage_location,
        }

    def capture_all(self, results: list[CheckResult], run_id: str) -> Path:
        """
        Capture evidence for every result and write a manifest tying each
        control to its evidence file and hash — this manifest is itself
        the auditable index of "what evidence exists for this scan."
        """
        manifest_entries = [self.capture(r, run_id) for r in results]
        manifest = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(manifest_entries),
            "entries": manifest_entries,
        }

        manifest_path = self.output_dir / f"{run_id}_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        return manifest_path
