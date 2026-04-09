from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from api_drift_sentinel.actions import ActionDispatcher
from api_drift_sentinel.alerts import AlertDispatcher
from api_drift_sentinel.config import load_project_config
from api_drift_sentinel.diffing import diff_payloads
from api_drift_sentinel.intelligence import build_report
from api_drift_sentinel.models import DriftReport, SourceConfig
from api_drift_sentinel.proofs import ProofRunner
from api_drift_sentinel.reports import render_json, render_markdown
from api_drift_sentinel.scheduler import SchedulerService
from api_drift_sentinel.server import DashboardApplication, serve_dashboard
from api_drift_sentinel.services import ScanCoordinator
from api_drift_sentinel.storage import DriftRepository

app = typer.Typer(help="Monitor OpenAPI and HTML docs drift for integration-heavy teams.")
console = Console()


@app.command("init-db")
def init_db(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db", help="SQLite database path."),
) -> None:
    repository = DriftRepository(db)
    repository.init_db()
    console.print(f"Initialized database at [bold]{db}[/bold].")


@app.command()
def scan(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, readable=True),
    db: Path | None = typer.Option(None, "--db", help="Override database path from config."),
    source: list[str] = typer.Option(None, "--source", help="Only scan selected source names."),
    persist_unchanged: bool = typer.Option(
        False,
        "--persist-unchanged",
        help="Persist a new snapshot even when the normalized payload has not changed.",
    ),
) -> None:
    project = load_project_config(config)
    repository = DriftRepository(db or Path(project.db_path))
    repository.init_db()
    coordinator = ScanCoordinator(
        repository,
        AlertDispatcher(repository, console),
        ProofRunner(repository),
        ActionDispatcher(repository),
    )

    selected = _filter_sources(project.sources, source)
    if not selected:
        raise typer.BadParameter("No sources matched the provided filters.")

    results = coordinator.scan_sources(
        selected,
        persist_unchanged=persist_unchanged,
        triggered_by="manual",
        alert_sinks=project.alerts,
        action_targets=project.actions,
        continue_on_error=False,
    )

    for result in results:
        item = result.source
        current = result.current_snapshot
        previous = result.previous_snapshot
        counts = result.run.counts
        if current is None:
            console.print(f"[red]{item.name}[/red]: scan failed.")
            continue
        if previous is None:
            if result.report and result.report.findings:
                console.print(
                    f"[green]{item.name}[/green]: baseline snapshot stored as #{current.id} "
                    f"with active findings (breaking={counts['breaking']}, warning={counts['warning']}, info={counts['info']})."
                )
            else:
                console.print(f"[green]{item.name}[/green]: baseline snapshot stored as #{current.id}.")
            continue
        if not result.run.changed:
            if result.report and result.report.findings:
                console.print(
                    f"[blue]{item.name}[/blue]: unchanged snapshot #{current.id}, "
                    f"but active findings remain (breaking={counts['breaking']}, warning={counts['warning']}, info={counts['info']})."
                )
            else:
                console.print(
                    f"[blue]{item.name}[/blue]: unchanged, latest snapshot remains #{current.id}."
                )
            continue

        console.print(
            f"[yellow]{item.name}[/yellow]: changed, stored snapshot #{current.id} "
            f"(breaking={counts['breaking']}, warning={counts['warning']}, info={counts['info']})."
        )


@app.command()
def history(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
    source: str = typer.Option(..., "--source"),
    limit: int = typer.Option(10, "--limit", min=1, max=100),
) -> None:
    repository = DriftRepository(db)
    snapshots = repository.get_recent_snapshots(source, limit=limit)
    if not snapshots:
        console.print(f"No snapshots found for [bold]{source}[/bold].")
        raise typer.Exit(code=1)

    table = Table(title=f"Snapshot History: {source}")
    table.add_column("ID", justify="right")
    table.add_column("Fetched At")
    table.add_column("Hash")
    table.add_column("Kind")
    for snapshot in snapshots:
        table.add_row(
            str(snapshot.id),
            snapshot.fetched_at.isoformat(),
            snapshot.content_hash[:12],
            snapshot.kind.value,
        )
    console.print(table)


@app.command()
def report(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
    source: str = typer.Option(..., "--source"),
    left_id: int | None = typer.Option(None, "--left-id"),
    right_id: int | None = typer.Option(None, "--right-id"),
    output: Path | None = typer.Option(None, "--output"),
    format: str = typer.Option("markdown", "--format", help="markdown or json"),
) -> None:
    repository = DriftRepository(db)
    left_snapshot, right_snapshot = _resolve_report_snapshots(
        repository=repository,
        source=source,
        left_id=left_id,
        right_id=right_id,
    )
    source_config = repository.get_source_config(source)
    findings = diff_payloads(
        kind=right_snapshot.kind, left=left_snapshot.payload, right=right_snapshot.payload
    )
    compiled = build_report(
        source=source_config,
        left_snapshot_id=left_snapshot.id,
        right_snapshot_id=right_snapshot.id,
        left_fetched_at=left_snapshot.fetched_at,
        right_fetched_at=right_snapshot.fetched_at,
        findings=findings,
        current_payload=right_snapshot.payload,
    )
    rendered = render_json(compiled) if format == "json" else render_markdown(compiled)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"Wrote report to [bold]{output}[/bold].")
        return
    console.print(rendered)


@app.command("list-sources")
def list_sources(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
) -> None:
    repository = DriftRepository(db)
    sources = repository.list_sources()
    if not sources:
        console.print("No sources registered yet.")
        return
    table = Table(title="Tracked Sources")
    table.add_column("Name")
    table.add_column("Kind")
    table.add_column("URL")
    table.add_column("Description")
    for item in sources:
        table.add_row(item["name"], item["kind"], item["url"], item["description"])
    console.print(table)


@app.command()
def runs(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
    source: str | None = typer.Option(None, "--source"),
    limit: int = typer.Option(20, "--limit", min=1, max=200),
) -> None:
    repository = DriftRepository(db)
    runs = repository.get_recent_scan_runs(source_name=source, limit=limit)
    if not runs:
        console.print("No scan runs recorded yet.")
        return
    table = Table(title="Recent Scan Runs")
    table.add_column("ID", justify="right")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Trigger")
    table.add_column("Completed")
    table.add_column("Breaking")
    table.add_column("Warning")
    table.add_column("Info")
    for run in runs:
        counts = run.counts
        table.add_row(
            str(run.id),
            run.source_name,
            run.status.value,
            run.triggered_by,
            run.completed_at.isoformat(),
            str(counts["breaking"]),
            str(counts["warning"]),
            str(counts["info"]),
        )
    console.print(table)


@app.command()
def alerts(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
    source: str | None = typer.Option(None, "--source"),
    limit: int = typer.Option(20, "--limit", min=1, max=200),
) -> None:
    repository = DriftRepository(db)
    deliveries = repository.get_recent_alert_deliveries(source_name=source, limit=limit)
    if not deliveries:
        console.print("No alert deliveries recorded yet.")
        return
    table = Table(title="Alert Deliveries")
    table.add_column("ID", justify="right")
    table.add_column("Source")
    table.add_column("Sink")
    table.add_column("Status")
    table.add_column("Delivered")
    table.add_column("Detail")
    for delivery in deliveries:
        table.add_row(
            str(delivery.id),
            delivery.source_name,
            delivery.sink_name,
            delivery.status.value,
            delivery.delivered_at.isoformat(),
            delivery.detail or delivery.error_message or "",
        )
    console.print(table)


@app.command()
def proofs(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
    source: str | None = typer.Option(None, "--source"),
    limit: int = typer.Option(20, "--limit", min=1, max=200),
) -> None:
    repository = DriftRepository(db)
    executions = repository.get_recent_proof_executions(source_name=source, limit=limit)
    if not executions:
        console.print("No proof executions recorded yet.")
        return
    table = Table(title="Proof Executions")
    table.add_column("ID", justify="right")
    table.add_column("Source")
    table.add_column("Proof")
    table.add_column("Status")
    table.add_column("Executed")
    table.add_column("Detail")
    for item in executions:
        table.add_row(
            str(item.id),
            item.source_name,
            item.proof_name,
            item.status.value,
            item.executed_at.isoformat(),
            item.detail or item.error_message or "",
        )
    console.print(table)


@app.command()
def actions(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
    source: str | None = typer.Option(None, "--source"),
    limit: int = typer.Option(20, "--limit", min=1, max=200),
) -> None:
    repository = DriftRepository(db)
    executions = repository.get_recent_action_executions(source_name=source, limit=limit)
    if not executions:
        console.print("No action executions recorded yet.")
        return
    table = Table(title="Action Executions")
    table.add_column("ID", justify="right")
    table.add_column("Source")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Executed")
    table.add_column("Detail")
    for item in executions:
        table.add_row(
            str(item.id),
            item.source_name,
            item.target_name,
            item.status.value,
            item.executed_at.isoformat(),
            item.detail or item.error_message or item.external_id or "",
        )
    console.print(table)


@app.command()
def timeline(
    db: Path = typer.Option(Path(".drift-sentinel/drift.db"), "--db"),
    source: str | None = typer.Option(None, "--source"),
    limit: int = typer.Option(50, "--limit", min=1, max=500),
) -> None:
    repository = DriftRepository(db)
    events = repository.get_timeline_events(source_name=source, limit=limit)
    if not events:
        console.print("No timeline events recorded yet.")
        return
    table = Table(title="Audit Timeline")
    table.add_column("ID", justify="right")
    table.add_column("Source")
    table.add_column("Kind")
    table.add_column("Actor")
    table.add_column("Created")
    table.add_column("Summary")
    for event in events:
        table.add_row(
            str(event.id),
            event.source_name,
            event.event_kind.value,
            event.actor,
            event.created_at.isoformat(),
            event.summary,
        )
    console.print(table)


@app.command()
def schedule(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, readable=True),
    db: Path | None = typer.Option(None, "--db", help="Override database path from config."),
    once: bool = typer.Option(False, "--once", help="Run due sources once and exit."),
    force: bool = typer.Option(False, "--force", help="Ignore due times and scan every source."),
) -> None:
    project = load_project_config(config)
    repository = DriftRepository(db or Path(project.db_path))
    repository.init_db()
    coordinator = ScanCoordinator(
        repository,
        AlertDispatcher(repository, console),
        ProofRunner(repository),
        ActionDispatcher(repository),
    )
    scheduler = SchedulerService(project, repository, coordinator)
    if once:
        results = scheduler.run_due_sources(force=force)
        console.print(f"Executed {len(results)} scheduled source scans.")
        return

    console.print(
        f"Scheduler running with interval {project.scheduler.interval_seconds}s "
        f"and poll {project.scheduler.poll_seconds}s."
    )
    try:
        scheduler.run_forever()
    except KeyboardInterrupt:
        console.print("Scheduler stopped.")


@app.command()
def serve(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, readable=True),
    db: Path | None = typer.Option(None, "--db", help="Override database path from config."),
    host: str | None = typer.Option(None, "--host"),
    port: int | None = typer.Option(None, "--port", min=1, max=65535),
    scheduler: bool = typer.Option(False, "--scheduler", help="Run the scheduler in-process."),
) -> None:
    project = load_project_config(config)
    repository = DriftRepository(db or Path(project.db_path))
    repository.init_db()
    coordinator = ScanCoordinator(
        repository,
        AlertDispatcher(repository, console),
        ProofRunner(repository),
        ActionDispatcher(repository),
    )
    application = DashboardApplication(repository, project=project, coordinator=coordinator)

    scheduler_stop = None
    scheduler_thread = None
    if scheduler or project.scheduler.enabled:
        scheduler_service = SchedulerService(project, repository, coordinator)
        scheduler_thread, scheduler_stop = scheduler_service.start_background()
        console.print("Background scheduler started.")

    bind_host = host or project.dashboard.host
    bind_port = port or project.dashboard.port
    httpd = serve_dashboard(bind_host, bind_port, application)
    console.print(f"Dashboard available at http://{bind_host}:{bind_port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("Server stopped.")
    finally:
        httpd.server_close()
        if scheduler_stop is not None:
            scheduler_stop.set()
        if scheduler_thread is not None:
            scheduler_thread.join(timeout=5)


def _filter_sources(sources: list[SourceConfig], selected_names: list[str]) -> list[SourceConfig]:
    if not selected_names:
        return sources
    names = set(selected_names)
    return [source for source in sources if source.name in names]


def _resolve_report_snapshots(
    *,
    repository: DriftRepository,
    source: str,
    left_id: int | None,
    right_id: int | None,
):
    if right_id is not None:
        right_snapshot = repository.get_snapshot(right_id)
    else:
        recent = repository.get_recent_snapshots(source, limit=2)
        if len(recent) < 2:
            raise typer.BadParameter(
                f"Need at least two snapshots for {source!r} to create a report."
            )
        right_snapshot = recent[0]
        if left_id is None:
            left_snapshot = recent[1]
            return left_snapshot, right_snapshot

    if left_id is None:
        raise typer.BadParameter("--left-id is required when --right-id is provided.")

    left_snapshot = repository.get_snapshot(left_id)
    return left_snapshot, right_snapshot
