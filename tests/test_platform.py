from pathlib import Path
from urllib.parse import urlsplit

from api_drift_sentinel.actions import ActionDispatcher
from api_drift_sentinel.alerts import AlertDispatcher
from api_drift_sentinel.fetchers import normalize_openapi_document
from api_drift_sentinel.models import (
    ActionTargetConfig,
    ActionTargetKind,
    AlertSinkConfig,
    AlertSinkKind,
    FindingRule,
    ImpactMap,
    ProjectConfig,
    ProofCheckConfig,
    ProofCheckKind,
    SchedulerConfig,
    SourceConfig,
)
from api_drift_sentinel.proofs import ProofRunner
from api_drift_sentinel.scheduler import SchedulerService
from api_drift_sentinel.server import DashboardApplication
from api_drift_sentinel.services import ScanCoordinator
from api_drift_sentinel.storage import DriftRepository


FIXTURES = Path(__file__).parent / "fixtures"


def test_openapi_compatibility_engine_resolves_refs_and_detects_semantic_breaks() -> None:
    before = normalize_openapi_document(
        """
openapi: 3.0.3
info:
  title: Demo Widgets API
  version: "1"
components:
  schemas:
    CreateWidgetRequest:
      type: object
      required: [name]
      properties:
        name:
          type: string
        color:
          type: string
    Widget:
      type: object
      required: [id, status]
      properties:
        id:
          type: string
        status:
          type: string
          enum: [active, paused]
paths:
  /widgets:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/CreateWidgetRequest"
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Widget"
"""
    )
    after = normalize_openapi_document(
        """
openapi: 3.0.3
info:
  title: Demo Widgets API
  version: "2"
components:
  schemas:
    CreateWidgetRequest:
      type: object
      required: [name, color]
      properties:
        name:
          type: string
        color:
          type: string
    Widget:
      type: object
      required: [id]
      properties:
        id:
          type: string
        status:
          type: string
          enum: [active, paused, archived]
paths:
  /widgets:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/CreateWidgetRequest"
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Widget"
"""
    )

    from api_drift_sentinel.diffing import diff_openapi_payloads

    findings = diff_openapi_payloads(before, after)
    codes = {finding.code for finding in findings}

    assert "request-required-property-added" in codes
    assert "response-required-property-removed" in codes
    assert "response-enum-expanded" in codes


def test_scan_records_runs_and_alert_file_sink(tmp_path: Path) -> None:
    source_path = tmp_path / "demo_openapi.yaml"
    source_path.write_text(
        (FIXTURES / "openapi_before.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    db_path = tmp_path / "drift.db"
    alert_path = tmp_path / "alerts.jsonl"

    repository = DriftRepository(db_path)
    repository.init_db()
    coordinator = ScanCoordinator(repository, AlertDispatcher(repository))
    source = SourceConfig(name="demo-orders-api", kind="openapi", url=str(source_path))
    sink = AlertSinkConfig(
        name="file-alerts",
        kind=AlertSinkKind.FILE,
        target=str(alert_path),
    )

    coordinator.scan_source(source, alert_sinks=[sink])
    source_path.write_text(
        (FIXTURES / "openapi_after.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    result = coordinator.scan_source(source, alert_sinks=[sink])

    runs = repository.get_recent_scan_runs(source_name="demo-orders-api", limit=10)
    deliveries = repository.get_recent_alert_deliveries(source_name="demo-orders-api", limit=10)

    assert result.run.changed is True
    assert len(runs) == 2
    assert len(deliveries) == 1
    assert deliveries[0].status.value == "success"
    assert '"source_name": "demo-orders-api"' in alert_path.read_text(encoding="utf-8")


def test_scheduler_skips_recent_sources_unless_forced(tmp_path: Path) -> None:
    source_path = tmp_path / "demo_openapi.yaml"
    source_path.write_text(
        (FIXTURES / "openapi_before.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    db_path = tmp_path / "drift.db"

    repository = DriftRepository(db_path)
    repository.init_db()
    coordinator = ScanCoordinator(repository, AlertDispatcher(repository))
    source = SourceConfig(
        name="demo-orders-api",
        kind="openapi",
        url=str(source_path),
        schedule_interval_seconds=3600,
    )
    project = ProjectConfig(
        db_path=str(db_path),
        sources=[source],
        scheduler=SchedulerConfig(enabled=True, interval_seconds=3600, poll_seconds=1.0),
    )
    scheduler = SchedulerService(project, repository, coordinator)

    first = scheduler.run_due_sources(force=True)
    second = scheduler.run_due_sources(force=False)

    assert len(first) == 1
    assert second == []


def test_scan_enriches_deadlines_proofs_actions_and_timeline(tmp_path: Path) -> None:
    source_path = tmp_path / "vendor_page.html"
    source_path.write_text(
        """
<!DOCTYPE html>
<html>
  <body>
    <main>
      <h1>Vendor migration</h1>
      <p>Clients must migrate before January 1, 2099.</p>
    </main>
  </body>
</html>
""",
        encoding="utf-8",
    )
    db_path = tmp_path / "drift.db"
    action_file = tmp_path / "actions.md"

    repository = DriftRepository(db_path)
    repository.init_db()
    coordinator = ScanCoordinator(
        repository,
        AlertDispatcher(repository),
        ProofRunner(repository),
        ActionDispatcher(repository),
    )
    source = SourceConfig(
        name="vendor-docs",
        kind="html",
        url=str(source_path),
        impact=ImpactMap(
            services=["sync-engine"],
            repos=["acme/sync-service"],
            owners=["platform-oncall"],
            runbooks=["https://runbooks.example.com/vendor-migration"],
            customer_workflows=["checkout sync"],
        ),
        proof_checks=[
            ProofCheckConfig(
                name="smoke-command",
                kind=ProofCheckKind.COMMAND,
                command='python -c "print(\'ok\')"',
            )
        ],
    )
    actions = [
        ActionTargetConfig(
            name="file-worklog",
            kind=ActionTargetKind.FILE,
            target=str(action_file),
            min_severity="info",
        ),
        ActionTargetConfig(
            name="slack-route",
            kind=ActionTargetKind.SLACK_WEBHOOK,
            target="https://hooks.slack.test/services/example",
            dry_run=True,
            min_severity="info",
            owner_mentions={"platform-oncall": "@platform-oncall"},
        ),
        ActionTargetConfig(
            name="github-route",
            kind=ActionTargetKind.GITHUB_ISSUE,
            github_repo="acme/sync-service",
            dry_run=True,
            min_severity="info",
        ),
        ActionTargetConfig(
            name="jira-route",
            kind=ActionTargetKind.JIRA_ISSUE,
            target="https://jira.example.com",
            jira_project_key="OPS",
            dry_run=True,
            min_severity="info",
        ),
    ]

    result = coordinator.scan_source(source, action_targets=actions)

    assert result.report is not None
    codes = {finding.code for finding in result.report.findings}
    assert "deadline-detected" in codes
    assert result.report.recommended_actions
    assert result.proof_executions[0].status.value == "success"
    assert len(result.action_executions) == 4
    assert repository.get_timeline_events(source_name="vendor-docs", limit=20)
    assert "Owners: platform-oncall" in action_file.read_text(encoding="utf-8")


def test_noise_controls_baseline_and_suppression_apply(tmp_path: Path) -> None:
    source_path = tmp_path / "demo_openapi.yaml"
    source_path.write_text(
        (FIXTURES / "openapi_before.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    db_path = tmp_path / "drift.db"

    repository = DriftRepository(db_path)
    repository.init_db()
    coordinator = ScanCoordinator(
        repository,
        AlertDispatcher(repository),
        ProofRunner(repository),
        ActionDispatcher(repository),
    )
    source = SourceConfig(
        name="demo-orders-api",
        kind="openapi",
        url=str(source_path),
        suppression_rules=[
            FindingRule(name="suppress-version", finding_codes=["spec-version-changed"])
        ],
        baseline_rules=[
            FindingRule(
                name="accepted-request-change",
                finding_codes=["request-required-property-added"],
                schema_paths=["request body application/json.region"],
            )
        ],
        focus_endpoints=["POST /orders"],
    )

    coordinator.scan_source(source)
    source_path.write_text(
        (FIXTURES / "openapi_after.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    result = coordinator.scan_source(source)

    assert result.report is not None
    codes = {finding.code for finding in result.report.findings}
    assert "spec-version-changed" not in codes
    assert "response-removed" not in codes
    assert any(
        finding.code == "request-required-property-added" and finding.severity == "info"
        for finding in result.report.findings
    )


def test_dashboard_application_exposes_json_endpoints(tmp_path: Path) -> None:
    source_path = tmp_path / "demo_openapi.yaml"
    source_path.write_text(
        (FIXTURES / "openapi_before.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    db_path = tmp_path / "drift.db"

    repository = DriftRepository(db_path)
    repository.init_db()
    coordinator = ScanCoordinator(
        repository,
        AlertDispatcher(repository),
        ProofRunner(repository),
        ActionDispatcher(repository),
    )
    source = SourceConfig(
        name="demo-orders-api",
        kind="openapi",
        url=str(source_path),
        impact=ImpactMap(owners=["platform-oncall"]),
    )
    project = ProjectConfig(
        db_path=str(db_path),
        sources=[source],
        actions=[
            ActionTargetConfig(
                name="slack-route",
                kind=ActionTargetKind.SLACK_WEBHOOK,
                target="https://hooks.slack.test/services/example",
                dry_run=True,
            )
        ],
    )
    coordinator.scan_source(source)

    app = DashboardApplication(repository, project=project, coordinator=coordinator)

    health_status, _, health_body = _call_wsgi(app, "/api/health")
    sources_status, _, sources_body = _call_wsgi(app, "/api/sources")
    timeline_status, _, timeline_body = _call_wsgi(app, "/api/timeline")

    source_path.write_text(
        (FIXTURES / "openapi_after.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    scan_status, _, scan_body = _call_wsgi(app, "/api/scan?source=demo-orders-api", method="POST")
    actions_status, _, actions_body = _call_wsgi(app, "/api/actions")

    assert health_status.startswith("200")
    assert health_body["status"] == "ok"
    assert sources_status.startswith("200")
    assert sources_body[0]["name"] == "demo-orders-api"
    assert sources_body[0]["impact"]["owners"] == ["platform-oncall"]
    assert timeline_status.startswith("200")
    assert timeline_body
    assert scan_status.startswith("200")
    assert scan_body[0]["run"]["changed"] is True
    assert actions_status.startswith("200")
    assert actions_body


def _call_wsgi(app, raw_path: str, method: str = "GET"):
    parts = urlsplit(raw_path)
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    body = b"".join(
        app(
            {
                "REQUEST_METHOD": method,
                "PATH_INFO": parts.path,
                "QUERY_STRING": parts.query,
            },
            start_response,
        )
    )
    return captured["status"], dict(captured["headers"]), __import__("json").loads(body.decode("utf-8"))
