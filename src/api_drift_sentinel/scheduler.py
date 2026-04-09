from __future__ import annotations

import threading
from datetime import datetime, timezone

from api_drift_sentinel.models import ProjectConfig, SourceConfig, SourceScanResult
from api_drift_sentinel.services import ScanCoordinator
from api_drift_sentinel.storage import DriftRepository


class SchedulerService:
    def __init__(
        self,
        project: ProjectConfig,
        repository: DriftRepository,
        coordinator: ScanCoordinator,
    ) -> None:
        self.project = project
        self.repository = repository
        self.coordinator = coordinator

    def run_due_sources(self, *, force: bool = False) -> list[SourceScanResult]:
        now = datetime.now(timezone.utc)
        results: list[SourceScanResult] = []
        for source in self.project.sources:
            if force or self._is_due(source, now):
                try:
                    result = self.coordinator.scan_source(
                        source,
                        persist_unchanged=False,
                        triggered_by="scheduler",
                        alert_sinks=self.project.alerts,
                        action_targets=self.project.actions,
                    )
                except Exception:
                    continue
                results.append(result)
        return results

    def run_forever(self, stop_event: threading.Event | None = None) -> None:
        local_stop = stop_event or threading.Event()
        if self.project.scheduler.run_on_startup:
            self.run_due_sources(force=False)

        while not local_stop.is_set():
            self.run_due_sources(force=False)
            local_stop.wait(self.project.scheduler.poll_seconds)

    def start_background(self) -> tuple[threading.Thread, threading.Event]:
        stop_event = threading.Event()
        thread = threading.Thread(
            target=self.run_forever,
            args=(stop_event,),
            name="api-drift-scheduler",
            daemon=True,
        )
        thread.start()
        return thread, stop_event

    def _is_due(self, source: SourceConfig, now: datetime) -> bool:
        last_run = self.repository.get_latest_scan_run(source.name)
        if last_run is None:
            return True
        interval_seconds = source.schedule_interval_seconds or self.project.scheduler.interval_seconds
        elapsed = (now - last_run.completed_at).total_seconds()
        return elapsed >= interval_seconds
