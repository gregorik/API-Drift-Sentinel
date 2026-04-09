from __future__ import annotations

import json
from html import escape
from typing import Any
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIServer, make_server

from api_drift_sentinel.models import ProjectConfig
from api_drift_sentinel.services import ScanCoordinator
from api_drift_sentinel.storage import DriftRepository


class DashboardApplication:
    def __init__(
        self,
        repository: DriftRepository,
        *,
        project: ProjectConfig | None = None,
        coordinator: ScanCoordinator | None = None,
    ) -> None:
        self.repository = repository
        self.project = project
        self.coordinator = coordinator

    def __call__(self, environ: dict[str, Any], start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        query = parse_qs(environ.get("QUERY_STRING", ""))

        if path == "/":
            body = self._render_dashboard()
            return _html_response(start_response, body)
        if path == "/api/health":
            return _json_response(start_response, {"status": "ok"})
        if path == "/api/sources":
            return _json_response(start_response, self.repository.get_source_summaries())
        if path == "/api/runs":
            source_name = query.get("source", [None])[0]
            runs = self.repository.get_recent_scan_runs(source_name=source_name, limit=25)
            return _json_response(start_response, [run.model_dump(mode="json") for run in runs])
        if path == "/api/alerts":
            source_name = query.get("source", [None])[0]
            deliveries = self.repository.get_recent_alert_deliveries(
                source_name=source_name, limit=25
            )
            return _json_response(
                start_response, [delivery.model_dump(mode="json") for delivery in deliveries]
            )
        if path == "/api/proofs":
            source_name = query.get("source", [None])[0]
            proofs = self.repository.get_recent_proof_executions(source_name=source_name, limit=25)
            return _json_response(start_response, [item.model_dump(mode="json") for item in proofs])
        if path == "/api/actions":
            source_name = query.get("source", [None])[0]
            actions = self.repository.get_recent_action_executions(source_name=source_name, limit=25)
            return _json_response(start_response, [item.model_dump(mode="json") for item in actions])
        if path == "/api/timeline":
            source_name = query.get("source", [None])[0]
            events = self.repository.get_timeline_events(source_name=source_name, limit=50)
            return _json_response(start_response, [item.model_dump(mode="json") for item in events])
        if path.startswith("/api/sources/"):
            source_name = path.split("/", 3)[3]
            return _json_response(start_response, self._source_detail(source_name))
        if path == "/api/scan" and method == "POST":
            if self.project is None or self.coordinator is None:
                return _json_response(
                    start_response,
                    {"error": "scan endpoint is unavailable without project config"},
                    status="503 Service Unavailable",
                )
            source_name = query.get("source", [None])[0]
            sources = self.project.sources
            if source_name is not None:
                sources = [source for source in self.project.sources if source.name == source_name]
            results = self.coordinator.scan_sources(
                sources,
                triggered_by="dashboard",
                alert_sinks=self.project.alerts,
                action_targets=self.project.actions,
                continue_on_error=False,
            )
            return _json_response(
                start_response,
                [result.model_dump(mode="json") for result in results],
            )
        return _json_response(start_response, {"error": "not found"}, status="404 Not Found")

    def _render_dashboard(self) -> str:
        summaries = self.repository.get_source_summaries()
        runs = self.repository.get_recent_scan_runs(limit=15)
        alerts = self.repository.get_recent_alert_deliveries(limit=15)
        actions = self.repository.get_recent_action_executions(limit=15)

        source_rows = "\n".join(
            (
                "<tr>"
                f"<td>{escape(str(item['name']))}</td>"
                f"<td>{escape(str(item['kind']))}</td>"
                f"<td class=\"cell-wrap\">{escape(', '.join(item.get('impact', {}).get('owners', [])) or '-')}</td>"
                f"<td class=\"cell-wrap\"><a href=\"{escape(str(item['url']))}\">{escape(str(item['url']))}</a></td>"
                f"<td class=\"cell-tight\">{escape(str(item.get('latest_snapshot_id') or '-'))}</td>"
                f"<td class=\"cell-tight\">{escape(str((item.get('latest_run') or {}).get('status', '-')))}</td>"
                f"<td class=\"cell-tight\">{escape(str((item.get('latest_run') or {}).get('changed', '-')))}</td>"
                "</tr>"
            )
            for item in summaries
        )
        run_rows = "\n".join(
            (
                "<tr>"
                f"<td>{escape(run.source_name)}</td>"
                f"<td class=\"cell-tight\">{escape(run.status.value)}</td>"
                f"<td class=\"cell-tight\">{escape(run.triggered_by)}</td>"
                f"<td class=\"cell-nowrap\">{escape(run.completed_at.isoformat())}</td>"
                f"<td class=\"cell-tight\">{escape(str(run.counts['breaking']))}</td>"
                f"<td class=\"cell-tight\">{escape(str(run.counts['warning']))}</td>"
                f"<td class=\"cell-tight\">{escape(str(run.counts['info']))}</td>"
                "</tr>"
            )
            for run in runs
        )
        alert_rows = "\n".join(
            (
                "<tr>"
                f"<td>{escape(alert.source_name)}</td>"
                f"<td>{escape(alert.sink_name)}</td>"
                f"<td class=\"cell-tight\">{escape(alert.status.value)}</td>"
                f"<td class=\"cell-nowrap\">{escape(alert.delivered_at.isoformat())}</td>"
                f"<td class=\"cell-wrap\">{escape(alert.detail or alert.error_message or '-')}</td>"
                "</tr>"
            )
            for alert in alerts
        )
        action_rows = "\n".join(
            (
                "<tr>"
                f"<td>{escape(action.source_name)}</td>"
                f"<td>{escape(action.target_name)}</td>"
                f"<td class=\"cell-tight\">{escape(action.status.value)}</td>"
                f"<td class=\"cell-nowrap\">{escape(action.executed_at.isoformat())}</td>"
                f"<td class=\"cell-wrap\">{escape(action.detail or action.error_message or action.external_id or '-')}</td>"
                "</tr>"
            )
            for action in actions
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="refresh" content="30" />
  <title>API Drift Sentinel Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4efe7;
      --card: #fffaf4;
      --ink: #1e1a17;
      --muted: #6d6256;
      --accent: #2b6f52;
      --line: #d8c9b8;
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", sans-serif;
      background: radial-gradient(circle at top, #fff7e8 0%, var(--bg) 45%, #ece1d2 100%);
      color: var(--ink);
    }}
    .wrap {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 20px 48px;
      overflow-x: clip;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 2rem;
      letter-spacing: 0.02em;
    }}
    p {{
      color: var(--muted);
      margin: 0 0 24px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      min-width: 0;
      overflow: hidden;
      box-shadow: 0 12px 30px rgba(58, 46, 30, 0.08);
    }}
    .card h2 {{
      margin: 0 0 14px;
      font-size: 1.15rem;
    }}
    .table-wrap {{
      width: 100%;
      overflow-x: auto;
      overflow-y: hidden;
      border-radius: 12px;
      -webkit-overflow-scrolling: touch;
    }}
    table {{
      width: max-content;
      min-width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }}
    th, td {{
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.04em;
    }}
    .cell-tight {{
      white-space: nowrap;
      width: 1%;
    }}
    .cell-nowrap {{
      white-space: nowrap;
    }}
    .cell-wrap {{
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    a {{
      color: var(--accent);
      text-decoration: none;
      overflow-wrap: anywhere;
    }}
    code {{
      background: #f0e7db;
      padding: 2px 6px;
      border-radius: 999px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>API Drift Sentinel</h1>
    <p>Dashboard, scheduler surface, and alert delivery history. Auto-refreshes every 30 seconds.</p>
    <div class="grid">
      <section class="card">
        <h2>Tracked Sources</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Kind</th><th>Owners</th><th>URL</th><th>Snapshot</th><th>Status</th><th>Changed</th></tr></thead>
            <tbody>{source_rows or '<tr><td colspan="7">No sources yet.</td></tr>'}</tbody>
          </table>
        </div>
      </section>
      <section class="card">
        <h2>Recent Runs</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Source</th><th>Status</th><th>Trigger</th><th>Completed</th><th>Breaking</th><th>Warning</th><th>Info</th></tr></thead>
            <tbody>{run_rows or '<tr><td colspan="7">No runs recorded.</td></tr>'}</tbody>
          </table>
        </div>
      </section>
      <section class="card" style="grid-column: 1 / -1;">
        <h2>Recent Alerts</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Source</th><th>Sink</th><th>Status</th><th>Delivered</th><th>Detail</th></tr></thead>
            <tbody>{alert_rows or '<tr><td colspan="5">No alerts delivered.</td></tr>'}</tbody>
          </table>
        </div>
        <h2>Recent Actions</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Source</th><th>Target</th><th>Status</th><th>Executed</th><th>Detail</th></tr></thead>
            <tbody>{action_rows or '<tr><td colspan="5">No actions executed.</td></tr>'}</tbody>
          </table>
        </div>
        <p>JSON endpoints: <code>/api/sources</code>, <code>/api/runs</code>, <code>/api/alerts</code>, <code>/api/proofs</code>, <code>/api/actions</code>, <code>/api/timeline</code>, <code>/api/health</code>.</p>
      </section>
    </div>
  </div>
</body>
</html>"""

    def _source_detail(self, source_name: str) -> dict[str, object]:
        summaries = {item["name"]: item for item in self.repository.get_source_summaries()}
        summary = summaries.get(source_name)
        if summary is None:
            return {"error": f"Unknown source {source_name!r}"}
        snapshots = self.repository.get_recent_snapshots(source_name, limit=10)
        runs = self.repository.get_recent_scan_runs(source_name=source_name, limit=10)
        alerts = self.repository.get_recent_alert_deliveries(source_name=source_name, limit=10)
        proofs = self.repository.get_recent_proof_executions(source_name=source_name, limit=10)
        actions = self.repository.get_recent_action_executions(source_name=source_name, limit=10)
        timeline = self.repository.get_timeline_events(source_name=source_name, limit=25)
        return {
            "source": summary,
            "snapshots": [snapshot.model_dump(mode="json") for snapshot in snapshots],
            "runs": [run.model_dump(mode="json") for run in runs],
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
            "proofs": [item.model_dump(mode="json") for item in proofs],
            "actions": [item.model_dump(mode="json") for item in actions],
            "timeline": [item.model_dump(mode="json") for item in timeline],
        }


def serve_dashboard(host: str, port: int, application: DashboardApplication) -> WSGIServer:
    return make_server(host, port, application)


def _json_response(start_response, payload: object, status: str = "200 OK"):
    body = json.dumps(payload, indent=2, default=str).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    start_response(status, headers)
    return [body]


def _html_response(start_response, html: str, status: str = "200 OK"):
    body = html.encode("utf-8")
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    start_response(status, headers)
    return [body]
