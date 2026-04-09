from __future__ import annotations

from datetime import datetime, timezone

from api_drift_sentinel.actions import ActionDispatcher
from api_drift_sentinel.alerts import AlertDispatcher
from api_drift_sentinel.diffing import diff_payloads
from api_drift_sentinel.fetchers import fetch_snapshot
from api_drift_sentinel.intelligence import build_report
from api_drift_sentinel.models import (
    RunStatus,
    ActionTargetConfig,
    SourceConfig,
    SourceScanResult,
)
from api_drift_sentinel.proofs import ProofRunner
from api_drift_sentinel.storage import DriftRepository


class ScanCoordinator:
    def __init__(
        self,
        repository: DriftRepository,
        alert_dispatcher: AlertDispatcher | None = None,
        proof_runner: ProofRunner | None = None,
        action_dispatcher: ActionDispatcher | None = None,
    ) -> None:
        self.repository = repository
        self.alert_dispatcher = alert_dispatcher
        self.proof_runner = proof_runner
        self.action_dispatcher = action_dispatcher

    def scan_source(
        self,
        source: SourceConfig,
        *,
        persist_unchanged: bool = False,
        triggered_by: str = "manual",
        alert_sinks=None,
        action_targets: list[ActionTargetConfig] | None = None,
    ) -> SourceScanResult:
        started_at = datetime.now(timezone.utc)
        self.repository.upsert_source(source)

        try:
            snapshot = fetch_snapshot(source)
            current, previous, changed = self.repository.save_snapshot(
                snapshot, persist_unchanged=persist_unchanged
            )
            previous_snapshot = previous or current
            findings = (
                diff_payloads(kind=source.kind, left=previous.payload, right=current.payload)
                if previous is not None and changed
                else []
            )
            report = build_report(
                source=source,
                left_snapshot_id=previous_snapshot.id,
                right_snapshot_id=current.id,
                left_fetched_at=previous_snapshot.fetched_at,
                right_fetched_at=current.fetched_at,
                findings=findings,
                current_payload=current.payload,
            )

            run = self.repository.record_scan_run(
                source_name=source.name,
                kind=source.kind.value,
                status=RunStatus.SUCCESS,
                triggered_by=triggered_by,
                started_at=started_at.isoformat(),
                completed_at=datetime.now(timezone.utc).isoformat(),
                snapshot_id=current.id,
                previous_snapshot_id=previous.id if previous else None,
                changed=changed,
                content_hash=current.content_hash,
                findings=report.findings,
            )
            result = SourceScanResult(
                source=source,
                run=run,
                current_snapshot=current,
                previous_snapshot=previous,
                report=report,
            )
            if self.proof_runner:
                result.proof_executions = self.proof_runner.run(
                    source=source,
                    scan_run_id=run.id,
                    snapshot_payload=current.payload,
                )
            if self.alert_dispatcher and alert_sinks:
                result.alert_deliveries = self.alert_dispatcher.dispatch(result, alert_sinks)
            if self.action_dispatcher and action_targets:
                selected_targets = _select_action_targets(source, action_targets)
                result.action_executions = self.action_dispatcher.dispatch(result, selected_targets)
            return result
        except Exception as exc:
            self.repository.record_scan_run(
                source_name=source.name,
                kind=source.kind.value,
                status=RunStatus.ERROR,
                triggered_by=triggered_by,
                started_at=started_at.isoformat(),
                completed_at=datetime.now(timezone.utc).isoformat(),
                snapshot_id=None,
                previous_snapshot_id=None,
                changed=False,
                content_hash=None,
                findings=[],
                error_message=str(exc),
            )
            raise RuntimeError(f"Scan failed for {source.name}: {exc}") from exc

    def scan_sources(
        self,
        sources: list[SourceConfig],
        *,
        persist_unchanged: bool = False,
        triggered_by: str = "manual",
        alert_sinks=None,
        action_targets: list[ActionTargetConfig] | None = None,
        continue_on_error: bool = False,
    ) -> list[SourceScanResult]:
        results: list[SourceScanResult] = []
        for source in sources:
            try:
                results.append(
                    self.scan_source(
                        source,
                        persist_unchanged=persist_unchanged,
                        triggered_by=triggered_by,
                        alert_sinks=alert_sinks,
                        action_targets=action_targets,
                    )
                )
            except Exception:
                if not continue_on_error:
                    raise
        return results


def _select_action_targets(
    source: SourceConfig, action_targets: list[ActionTargetConfig]
) -> list[ActionTargetConfig]:
    if not source.action_target_names:
        return action_targets
    allowed = set(source.action_target_names)
    return [item for item in action_targets if item.name in allowed]
