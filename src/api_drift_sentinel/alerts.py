from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console

from api_drift_sentinel.models import (
    AlertDeliveryRecord,
    AlertFormat,
    AlertSinkConfig,
    DriftReport,
    RunStatus,
    SourceScanResult,
    severity_meets_threshold,
    severity_rank,
)
from api_drift_sentinel.reports import render_json, render_markdown
from api_drift_sentinel.storage import DriftRepository


class AlertDispatcher:
    def __init__(self, repository: DriftRepository, console: Console | None = None) -> None:
        self.repository = repository
        self.console = console or Console()

    def dispatch(
        self, result: SourceScanResult, sinks: list[AlertSinkConfig]
    ) -> list[AlertDeliveryRecord]:
        if result.report is None or not result.report.findings:
            return []

        deliveries: list[AlertDeliveryRecord] = []
        for sink in sinks:
            threshold = _max_threshold(sink.min_severity, result.source.alert_severity_threshold)
            filtered_report = _filter_report(result.report, threshold)
            if not filtered_report.findings:
                continue

            delivered_at = datetime.now(timezone.utc).isoformat()
            try:
                detail = self._deliver(sink, filtered_report)
                delivery = self.repository.record_alert_delivery(
                    scan_run_id=result.run.id,
                    source_name=result.source.name,
                    sink_name=sink.name,
                    sink_kind=sink.kind,
                    status=RunStatus.SUCCESS,
                    delivered_at=delivered_at,
                    payload_format=sink.format,
                    detail=detail,
                )
            except Exception as exc:
                delivery = self.repository.record_alert_delivery(
                    scan_run_id=result.run.id,
                    source_name=result.source.name,
                    sink_name=sink.name,
                    sink_kind=sink.kind,
                    status=RunStatus.ERROR,
                    delivered_at=delivered_at,
                    payload_format=sink.format,
                    error_message=str(exc),
                )
            deliveries.append(delivery)
        return deliveries

    def _deliver(self, sink: AlertSinkConfig, report: DriftReport) -> str:
        payload = _render_payload(report, sink.format)
        if sink.kind.value == "console":
            self.console.print(payload)
            return "printed to console"
        if sink.kind.value == "file":
            if sink.target is None:
                raise ValueError(f"Alert sink {sink.name!r} requires a target path")
            target = Path(sink.target)
            target.parent.mkdir(parents=True, exist_ok=True)
            if sink.format == AlertFormat.JSON:
                with target.open("a", encoding="utf-8") as handle:
                    handle.write(payload)
                    handle.write("\n")
            else:
                with target.open("a", encoding="utf-8") as handle:
                    handle.write(payload)
                    handle.write("\n\n")
            return str(target)
        if sink.kind.value == "webhook":
            if sink.target is None:
                raise ValueError(f"Alert sink {sink.name!r} requires a target URL")
            with httpx.Client(timeout=sink.timeout_seconds, follow_redirects=True) as client:
                response = client.post(
                    sink.target,
                    headers=sink.headers,
                    json=_build_webhook_payload(report),
                )
                response.raise_for_status()
                return f"webhook {response.status_code}"
        raise ValueError(f"Unsupported alert sink kind: {sink.kind}")


def _render_payload(report: DriftReport, format: AlertFormat) -> str:
    if format == AlertFormat.MARKDOWN:
        return render_markdown(report)
    return render_json(report)


def _build_webhook_payload(report: DriftReport) -> dict[str, object]:
    return {
        "source": report.source_name,
        "kind": report.kind.value,
        "left_snapshot_id": report.left_snapshot_id,
        "right_snapshot_id": report.right_snapshot_id,
        "left_fetched_at": report.left_fetched_at.isoformat(),
        "right_fetched_at": report.right_fetched_at.isoformat(),
        "counts": report.counts,
        "findings": [finding.model_dump(mode="json") for finding in report.findings],
    }


def _filter_report(report: DriftReport, threshold: str) -> DriftReport:
    filtered = [
        finding for finding in report.findings if severity_meets_threshold(finding.severity, threshold)
    ]
    return DriftReport(
        source_name=report.source_name,
        kind=report.kind,
        left_snapshot_id=report.left_snapshot_id,
        right_snapshot_id=report.right_snapshot_id,
        left_fetched_at=report.left_fetched_at,
        right_fetched_at=report.right_fetched_at,
        findings=filtered,
        impact=report.impact,
        deadlines=report.deadlines,
        vendor=report.vendor,
        recommended_actions=report.recommended_actions,
    )


def _max_threshold(left: str, right: str) -> str:
    return left if severity_rank(left) >= severity_rank(right) else right
