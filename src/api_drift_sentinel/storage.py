from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from api_drift_sentinel.models import (
    ActionExecutionRecord,
    ActionTargetKind,
    AlertDeliveryRecord,
    AlertFormat,
    AlertSinkKind,
    DriftFinding,
    ProofCheckKind,
    ProofExecutionRecord,
    RunStatus,
    ScanRunRecord,
    SnapshotEnvelope,
    SnapshotRecord,
    SourceConfig,
    TimelineEventKind,
    TimelineEventRecord,
)


class DriftRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    name TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    url TEXT NOT NULL,
                    description TEXT,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    url TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(source_name) REFERENCES sources(name)
                );

                CREATE INDEX IF NOT EXISTS idx_snapshots_source_name_fetched_at
                    ON snapshots(source_name, fetched_at DESC);

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    triggered_by TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    snapshot_id INTEGER,
                    previous_snapshot_id INTEGER,
                    changed INTEGER NOT NULL DEFAULT 0,
                    content_hash TEXT,
                    findings_json TEXT NOT NULL DEFAULT '[]',
                    error_message TEXT,
                    FOREIGN KEY(source_name) REFERENCES sources(name),
                    FOREIGN KEY(snapshot_id) REFERENCES snapshots(id),
                    FOREIGN KEY(previous_snapshot_id) REFERENCES snapshots(id)
                );

                CREATE INDEX IF NOT EXISTS idx_scan_runs_source_name_completed_at
                    ON scan_runs(source_name, completed_at DESC);

                CREATE TABLE IF NOT EXISTS alert_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    source_name TEXT NOT NULL,
                    sink_name TEXT NOT NULL,
                    sink_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    delivered_at TEXT NOT NULL,
                    payload_format TEXT NOT NULL,
                    error_message TEXT,
                    detail TEXT,
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
                    FOREIGN KEY(source_name) REFERENCES sources(name)
                );

                CREATE INDEX IF NOT EXISTS idx_alert_deliveries_scan_run_id
                    ON alert_deliveries(scan_run_id);

                CREATE TABLE IF NOT EXISTS proof_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    source_name TEXT NOT NULL,
                    proof_name TEXT NOT NULL,
                    proof_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    detail TEXT,
                    error_message TEXT,
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
                    FOREIGN KEY(source_name) REFERENCES sources(name)
                );

                CREATE INDEX IF NOT EXISTS idx_proof_executions_scan_run_id
                    ON proof_executions(scan_run_id);

                CREATE TABLE IF NOT EXISTS action_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    source_name TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    external_id TEXT,
                    detail TEXT,
                    error_message TEXT,
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
                    FOREIGN KEY(source_name) REFERENCES sources(name)
                );

                CREATE INDEX IF NOT EXISTS idx_action_executions_scan_run_id
                    ON action_executions(scan_run_id);

                CREATE TABLE IF NOT EXISTS timeline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    scan_run_id INTEGER,
                    FOREIGN KEY(source_name) REFERENCES sources(name),
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
                );

                CREATE INDEX IF NOT EXISTS idx_timeline_events_source_name_created_at
                    ON timeline_events(source_name, created_at DESC);
                """
            )

    def upsert_source(self, source: SourceConfig) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sources(name, kind, url, description, config_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    kind = excluded.kind,
                    url = excluded.url,
                    description = excluded.description,
                    config_json = excluded.config_json
                """,
                (
                    source.name,
                    source.kind.value,
                    source.url,
                    source.description,
                    json.dumps(source.model_dump(mode="json"), sort_keys=True),
                ),
            )
        self.append_timeline_event(
            source_name=source.name,
            event_kind=TimelineEventKind.SOURCE_SYNCED,
            actor="system",
            summary="Source configuration synced.",
            payload={"kind": source.kind.value, "url": source.url},
        )

    def get_source_config(self, source_name: str) -> SourceConfig:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT config_json
                FROM sources
                WHERE name = ?
                """,
                (source_name,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Source {source_name!r} not found")
        return SourceConfig.model_validate(json.loads(row["config_json"]))

    def list_sources(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT name, kind, url, COALESCE(description, '') AS description, config_json
                FROM sources
                ORDER BY name ASC
                """
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            config = SourceConfig.model_validate(json.loads(row["config_json"]))
            items.append(
                {
                    "name": row["name"],
                    "kind": row["kind"],
                    "url": row["url"],
                    "description": row["description"],
                    "vendor": config.vendor.value if config.vendor else None,
                    "impact": config.impact.model_dump(mode="json"),
                }
            )
        return items

    def get_latest_snapshot(self, source_name: str) -> SnapshotRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, source_name, kind, url, fetched_at, content_hash, payload_json
                FROM snapshots
                WHERE source_name = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (source_name,),
            ).fetchone()
        return self._row_to_snapshot(row) if row else None

    def get_recent_snapshots(self, source_name: str, limit: int = 10) -> list[SnapshotRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, source_name, kind, url, fetched_at, content_hash, payload_json
                FROM snapshots
                WHERE source_name = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (source_name, limit),
            ).fetchall()
        return [self._row_to_snapshot(row) for row in rows]

    def get_snapshot(self, snapshot_id: int) -> SnapshotRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, source_name, kind, url, fetched_at, content_hash, payload_json
                FROM snapshots
                WHERE id = ?
                """,
                (snapshot_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Snapshot {snapshot_id} not found")
        return self._row_to_snapshot(row)

    def save_snapshot(
        self, snapshot: SnapshotEnvelope, *, persist_unchanged: bool = False
    ) -> tuple[SnapshotRecord, SnapshotRecord | None, bool]:
        previous = self.get_latest_snapshot(snapshot.source_name)
        changed = previous is None or previous.content_hash != snapshot.content_hash
        if not changed and previous is not None and not persist_unchanged:
            return previous, previous, False

        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO snapshots(source_name, kind, url, fetched_at, content_hash, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.source_name,
                    snapshot.kind.value,
                    snapshot.url,
                    snapshot.fetched_at.isoformat(),
                    snapshot.content_hash,
                    json.dumps(snapshot.payload, sort_keys=True),
                ),
            )
            snapshot_id = int(cursor.lastrowid)
        current = self.get_snapshot(snapshot_id)
        return current, previous, changed

    def record_scan_run(
        self,
        *,
        source_name: str,
        kind: str,
        status: RunStatus,
        triggered_by: str,
        started_at: str,
        completed_at: str,
        snapshot_id: int | None,
        previous_snapshot_id: int | None,
        changed: bool,
        content_hash: str | None,
        findings: list[DriftFinding],
        error_message: str | None = None,
    ) -> ScanRunRecord:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_runs(
                    source_name,
                    kind,
                    status,
                    triggered_by,
                    started_at,
                    completed_at,
                    snapshot_id,
                    previous_snapshot_id,
                    changed,
                    content_hash,
                    findings_json,
                    error_message
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_name,
                    kind,
                    status.value,
                    triggered_by,
                    started_at,
                    completed_at,
                    snapshot_id,
                    previous_snapshot_id,
                    int(changed),
                    content_hash,
                    json.dumps([finding.model_dump(mode="json") for finding in findings]),
                    error_message,
                ),
            )
            run_id = int(cursor.lastrowid)
        record = self.get_scan_run(run_id)
        self.append_timeline_event(
            source_name=source_name,
            event_kind=TimelineEventKind.SCAN_RECORDED,
            actor=triggered_by,
            summary=f"Scan recorded with status {status.value}.",
            payload={
                "status": status.value,
                "changed": changed,
                "counts": record.counts,
                "error_message": error_message,
            },
            scan_run_id=run_id,
        )
        return record

    def get_scan_run(self, run_id: int) -> ScanRunRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    source_name,
                    kind,
                    status,
                    triggered_by,
                    started_at,
                    completed_at,
                    snapshot_id,
                    previous_snapshot_id,
                    changed,
                    content_hash,
                    findings_json,
                    error_message
                FROM scan_runs
                WHERE id = ?
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Scan run {run_id} not found")
        return self._row_to_scan_run(row)

    def get_latest_scan_run(self, source_name: str) -> ScanRunRecord | None:
        runs = self.get_recent_scan_runs(source_name=source_name, limit=1)
        return runs[0] if runs else None

    def get_recent_scan_runs(
        self, *, source_name: str | None = None, limit: int = 20
    ) -> list[ScanRunRecord]:
        query = """
            SELECT
                id,
                source_name,
                kind,
                status,
                triggered_by,
                started_at,
                completed_at,
                snapshot_id,
                previous_snapshot_id,
                changed,
                content_hash,
                findings_json,
                error_message
            FROM scan_runs
        """
        params: tuple[object, ...]
        if source_name is None:
            query += " ORDER BY completed_at DESC LIMIT ?"
            params = (limit,)
        else:
            query += " WHERE source_name = ? ORDER BY completed_at DESC LIMIT ?"
            params = (source_name, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_scan_run(row) for row in rows]

    def record_alert_delivery(
        self,
        *,
        scan_run_id: int,
        source_name: str,
        sink_name: str,
        sink_kind: AlertSinkKind,
        status: RunStatus,
        delivered_at: str,
        payload_format: AlertFormat,
        error_message: str | None = None,
        detail: str | None = None,
    ) -> AlertDeliveryRecord:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO alert_deliveries(
                    scan_run_id,
                    source_name,
                    sink_name,
                    sink_kind,
                    status,
                    delivered_at,
                    payload_format,
                    error_message,
                    detail
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_run_id,
                    source_name,
                    sink_name,
                    sink_kind.value,
                    status.value,
                    delivered_at,
                    payload_format.value,
                    error_message,
                    detail,
                ),
            )
            delivery_id = int(cursor.lastrowid)
        record = self.get_alert_delivery(delivery_id)
        self.append_timeline_event(
            source_name=source_name,
            event_kind=TimelineEventKind.ALERT_DELIVERED,
            actor=sink_name,
            summary=f"Alert delivery {status.value} via {sink_kind.value}.",
            payload={"detail": detail, "error_message": error_message},
            scan_run_id=scan_run_id,
        )
        return record

    def get_alert_delivery(self, delivery_id: int) -> AlertDeliveryRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    scan_run_id,
                    source_name,
                    sink_name,
                    sink_kind,
                    status,
                    delivered_at,
                    payload_format,
                    error_message,
                    detail
                FROM alert_deliveries
                WHERE id = ?
                """,
                (delivery_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Alert delivery {delivery_id} not found")
        return self._row_to_alert_delivery(row)

    def get_recent_alert_deliveries(
        self, *, source_name: str | None = None, limit: int = 20
    ) -> list[AlertDeliveryRecord]:
        query = """
            SELECT
                id,
                scan_run_id,
                source_name,
                sink_name,
                sink_kind,
                status,
                delivered_at,
                payload_format,
                error_message,
                detail
            FROM alert_deliveries
        """
        params: tuple[object, ...]
        if source_name is None:
            query += " ORDER BY delivered_at DESC LIMIT ?"
            params = (limit,)
        else:
            query += " WHERE source_name = ? ORDER BY delivered_at DESC LIMIT ?"
            params = (source_name, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_alert_delivery(row) for row in rows]

    def record_proof_execution(
        self,
        *,
        scan_run_id: int,
        source_name: str,
        proof_name: str,
        proof_kind: ProofCheckKind,
        status: RunStatus,
        executed_at: str,
        detail: str | None = None,
        error_message: str | None = None,
    ) -> ProofExecutionRecord:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO proof_executions(
                    scan_run_id,
                    source_name,
                    proof_name,
                    proof_kind,
                    status,
                    executed_at,
                    detail,
                    error_message
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_run_id,
                    source_name,
                    proof_name,
                    proof_kind.value,
                    status.value,
                    executed_at,
                    detail,
                    error_message,
                ),
            )
            proof_id = int(cursor.lastrowid)
        record = self.get_proof_execution(proof_id)
        self.append_timeline_event(
            source_name=source_name,
            event_kind=TimelineEventKind.PROOF_EXECUTED,
            actor=proof_name,
            summary=f"Proof {status.value}: {proof_name}.",
            payload={"detail": detail, "error_message": error_message},
            scan_run_id=scan_run_id,
        )
        return record

    def get_proof_execution(self, proof_id: int) -> ProofExecutionRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    scan_run_id,
                    source_name,
                    proof_name,
                    proof_kind,
                    status,
                    executed_at,
                    detail,
                    error_message
                FROM proof_executions
                WHERE id = ?
                """,
                (proof_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Proof execution {proof_id} not found")
        return self._row_to_proof_execution(row)

    def get_recent_proof_executions(
        self, *, source_name: str | None = None, limit: int = 20
    ) -> list[ProofExecutionRecord]:
        query = """
            SELECT
                id,
                scan_run_id,
                source_name,
                proof_name,
                proof_kind,
                status,
                executed_at,
                detail,
                error_message
            FROM proof_executions
        """
        params: tuple[object, ...]
        if source_name is None:
            query += " ORDER BY executed_at DESC LIMIT ?"
            params = (limit,)
        else:
            query += " WHERE source_name = ? ORDER BY executed_at DESC LIMIT ?"
            params = (source_name, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_proof_execution(row) for row in rows]

    def record_action_execution(
        self,
        *,
        scan_run_id: int,
        source_name: str,
        target_name: str,
        target_kind: ActionTargetKind,
        status: RunStatus,
        executed_at: str,
        external_id: str | None = None,
        detail: str | None = None,
        error_message: str | None = None,
    ) -> ActionExecutionRecord:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO action_executions(
                    scan_run_id,
                    source_name,
                    target_name,
                    target_kind,
                    status,
                    executed_at,
                    external_id,
                    detail,
                    error_message
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_run_id,
                    source_name,
                    target_name,
                    target_kind.value,
                    status.value,
                    executed_at,
                    external_id,
                    detail,
                    error_message,
                ),
            )
            action_id = int(cursor.lastrowid)
        record = self.get_action_execution(action_id)
        self.append_timeline_event(
            source_name=source_name,
            event_kind=TimelineEventKind.ACTION_EXECUTED,
            actor=target_name,
            summary=f"Action {status.value}: {target_kind.value}.",
            payload={
                "detail": detail,
                "error_message": error_message,
                "external_id": external_id,
            },
            scan_run_id=scan_run_id,
        )
        return record

    def get_action_execution(self, action_id: int) -> ActionExecutionRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    scan_run_id,
                    source_name,
                    target_name,
                    target_kind,
                    status,
                    executed_at,
                    external_id,
                    detail,
                    error_message
                FROM action_executions
                WHERE id = ?
                """,
                (action_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Action execution {action_id} not found")
        return self._row_to_action_execution(row)

    def get_recent_action_executions(
        self, *, source_name: str | None = None, limit: int = 20
    ) -> list[ActionExecutionRecord]:
        query = """
            SELECT
                id,
                scan_run_id,
                source_name,
                target_name,
                target_kind,
                status,
                executed_at,
                external_id,
                detail,
                error_message
            FROM action_executions
        """
        params: tuple[object, ...]
        if source_name is None:
            query += " ORDER BY executed_at DESC LIMIT ?"
            params = (limit,)
        else:
            query += " WHERE source_name = ? ORDER BY executed_at DESC LIMIT ?"
            params = (source_name, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_action_execution(row) for row in rows]

    def append_timeline_event(
        self,
        *,
        source_name: str,
        event_kind: TimelineEventKind,
        actor: str,
        summary: str,
        payload: dict[str, Any],
        scan_run_id: int | None = None,
    ) -> TimelineEventRecord:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO timeline_events(
                    source_name,
                    event_kind,
                    created_at,
                    actor,
                    summary,
                    payload_json,
                    scan_run_id
                )
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
                """,
                (
                    source_name,
                    event_kind.value,
                    actor,
                    summary,
                    json.dumps(payload, sort_keys=True),
                    scan_run_id,
                ),
            )
            event_id = int(cursor.lastrowid)
        return self.get_timeline_event(event_id)

    def get_timeline_event(self, event_id: int) -> TimelineEventRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    source_name,
                    event_kind,
                    created_at,
                    actor,
                    summary,
                    payload_json,
                    scan_run_id
                FROM timeline_events
                WHERE id = ?
                """,
                (event_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Timeline event {event_id} not found")
        return self._row_to_timeline_event(row)

    def get_timeline_events(
        self, *, source_name: str | None = None, limit: int = 50
    ) -> list[TimelineEventRecord]:
        query = """
            SELECT
                id,
                source_name,
                event_kind,
                created_at,
                actor,
                summary,
                payload_json,
                scan_run_id
            FROM timeline_events
        """
        params: tuple[object, ...]
        if source_name is None:
            query += " ORDER BY created_at DESC, id DESC LIMIT ?"
            params = (limit,)
        else:
            query += " WHERE source_name = ? ORDER BY created_at DESC, id DESC LIMIT ?"
            params = (source_name, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_timeline_event(row) for row in rows]

    def get_source_summaries(self) -> list[dict[str, object]]:
        sources = self.list_sources()
        summaries: list[dict[str, object]] = []
        for item in sources:
            latest_snapshot = self.get_latest_snapshot(item["name"])
            latest_run = self.get_latest_scan_run(item["name"])
            latest_action = self.get_recent_action_executions(source_name=item["name"], limit=1)
            latest_proof = self.get_recent_proof_executions(source_name=item["name"], limit=1)
            summaries.append(
                {
                    **item,
                    "latest_snapshot_id": latest_snapshot.id if latest_snapshot else None,
                    "latest_snapshot_at": latest_snapshot.fetched_at if latest_snapshot else None,
                    "latest_run": latest_run.model_dump(mode="json") if latest_run else None,
                    "latest_action": latest_action[0].model_dump(mode="json") if latest_action else None,
                    "latest_proof": latest_proof[0].model_dump(mode="json") if latest_proof else None,
                }
            )
        return summaries

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _row_to_snapshot(self, row: sqlite3.Row) -> SnapshotRecord:
        return SnapshotRecord.model_validate(
            {
                "id": row["id"],
                "source_name": row["source_name"],
                "kind": row["kind"],
                "url": row["url"],
                "fetched_at": row["fetched_at"],
                "content_hash": row["content_hash"],
                "payload": json.loads(row["payload_json"]),
            }
        )

    def _row_to_scan_run(self, row: sqlite3.Row) -> ScanRunRecord:
        findings = [DriftFinding.model_validate(item) for item in json.loads(row["findings_json"])]
        return ScanRunRecord.model_validate(
            {
                "id": row["id"],
                "source_name": row["source_name"],
                "kind": row["kind"],
                "status": row["status"],
                "triggered_by": row["triggered_by"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "snapshot_id": row["snapshot_id"],
                "previous_snapshot_id": row["previous_snapshot_id"],
                "changed": bool(row["changed"]),
                "content_hash": row["content_hash"],
                "findings": findings,
                "error_message": row["error_message"],
            }
        )

    def _row_to_alert_delivery(self, row: sqlite3.Row) -> AlertDeliveryRecord:
        return AlertDeliveryRecord.model_validate(
            {
                "id": row["id"],
                "scan_run_id": row["scan_run_id"],
                "source_name": row["source_name"],
                "sink_name": row["sink_name"],
                "sink_kind": row["sink_kind"],
                "status": row["status"],
                "delivered_at": row["delivered_at"],
                "payload_format": row["payload_format"],
                "error_message": row["error_message"],
                "detail": row["detail"],
            }
        )

    def _row_to_proof_execution(self, row: sqlite3.Row) -> ProofExecutionRecord:
        return ProofExecutionRecord.model_validate(
            {
                "id": row["id"],
                "scan_run_id": row["scan_run_id"],
                "source_name": row["source_name"],
                "proof_name": row["proof_name"],
                "proof_kind": row["proof_kind"],
                "status": row["status"],
                "executed_at": row["executed_at"],
                "detail": row["detail"],
                "error_message": row["error_message"],
            }
        )

    def _row_to_action_execution(self, row: sqlite3.Row) -> ActionExecutionRecord:
        return ActionExecutionRecord.model_validate(
            {
                "id": row["id"],
                "scan_run_id": row["scan_run_id"],
                "source_name": row["source_name"],
                "target_name": row["target_name"],
                "target_kind": row["target_kind"],
                "status": row["status"],
                "executed_at": row["executed_at"],
                "external_id": row["external_id"],
                "detail": row["detail"],
                "error_message": row["error_message"],
            }
        )

    def _row_to_timeline_event(self, row: sqlite3.Row) -> TimelineEventRecord:
        return TimelineEventRecord.model_validate(
            {
                "id": row["id"],
                "source_name": row["source_name"],
                "event_kind": row["event_kind"],
                "created_at": row["created_at"],
                "actor": row["actor"],
                "summary": row["summary"],
                "payload": json.loads(row["payload_json"]),
                "scan_run_id": row["scan_run_id"],
            }
        )
