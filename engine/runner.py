"""
Parallel execution engine. Runs every resolved (control, check_function)
pair against a shared boto3 session and collects CheckResults.

Each check function is expected to have the signature:

    def check_xyz(session: boto3.Session) -> tuple[Status, str, dict]:
        # returns (status, human_readable_message, evidence_dict)

Using ThreadPoolExecutor is appropriate here because these are I/O-bound
AWS API calls, not CPU-bound work — this is what keeps a 20+ control scan
to a few seconds instead of running everything serially.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import boto3

from engine.loader import ControlsWithChecks
from engine.models import CheckResult, Status

logger = logging.getLogger(__name__)


class ComplianceRunner:
    def __init__(self, session: Optional[boto3.Session] = None, max_workers: int = 8):
        self.session = session or boto3.Session()
        self.max_workers = max_workers

    def _run_single(self, control, check_function) -> CheckResult:
        try:
            status, message, evidence = check_function(self.session)
            return CheckResult(control=control, status=status, message=message, evidence=evidence)
        except Exception as exc:  # noqa: BLE001 - a failing check must not kill the scan
            logger.exception("Check %s raised an exception", control.control_id)
            return CheckResult(
                control=control,
                status=Status.ERROR,
                message=f"Check raised an exception: {exc}",
                evidence={},
                error=str(exc),
            )

    def run(self, controls_with_checks: ControlsWithChecks) -> list[CheckResult]:
        results: list[CheckResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._run_single, control, func): control
                for control, func in controls_with_checks
            }
            for future in as_completed(futures):
                results.append(future.result())

        # Stable order for reporting: by framework, then control_id
        results.sort(key=lambda r: (r.control.framework, r.control.control_id))
        return results

    @staticmethod
    def summarize(results: list[CheckResult]) -> dict:
        total = len(results)
        passed = sum(1 for r in results if r.status == Status.PASS)
        failed = sum(1 for r in results if r.status == Status.FAIL)
        errored = sum(1 for r in results if r.status == Status.ERROR)
        na = sum(1 for r in results if r.status == Status.NOT_APPLICABLE)
        scored = total - na
        score_pct = round((passed / scored) * 100, 1) if scored else 0.0
        return {
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "errored": errored,
            "not_applicable": na,
            "compliance_score_pct": score_pct,
        }
