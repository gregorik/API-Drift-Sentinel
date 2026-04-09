from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["breaking", "warning", "info"]
Urgency = Literal["overdue", "immediate", "soon", "upcoming", "future", "none"]


class SourceKind(StrEnum):
    HTML = "html"
    OPENAPI = "openapi"


class AlertSinkKind(StrEnum):
    CONSOLE = "console"
    FILE = "file"
    WEBHOOK = "webhook"


class ActionTargetKind(StrEnum):
    FILE = "file"
    WEBHOOK = "webhook"
    SLACK_WEBHOOK = "slack_webhook"
    GITHUB_ISSUE = "github_issue"
    JIRA_ISSUE = "jira_issue"


class AlertFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"


class RunStatus(StrEnum):
    SUCCESS = "success"
    ERROR = "error"


class VendorKind(StrEnum):
    GENERIC = "generic"
    GITHUB = "github"
    SHOPIFY = "shopify"
    STRIPE = "stripe"
    SLACK = "slack"
    MONDAY = "monday"
    OPENAI = "openai"


class ProofCheckKind(StrEnum):
    COMMAND = "command"
    HTTP = "http"
    SAMPLE_SCHEMA = "sample_schema"


class TimelineEventKind(StrEnum):
    SOURCE_SYNCED = "source_synced"
    SCAN_RECORDED = "scan_recorded"
    ALERT_DELIVERED = "alert_delivered"
    PROOF_EXECUTED = "proof_executed"
    ACTION_EXECUTED = "action_executed"


class ImpactMap(BaseModel):
    services: list[str] = Field(default_factory=list)
    repos: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    runbooks: list[str] = Field(default_factory=list)
    customer_workflows: list[str] = Field(default_factory=list)


class FindingRule(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    finding_codes: list[str] = Field(default_factory=list)
    operations: list[str] = Field(default_factory=list)
    schema_paths: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    min_severity: Severity | None = None
    until: datetime | None = None
    reason: str | None = None


class ProofCheckConfig(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: ProofCheckKind
    command: str | None = None
    url: str | None = None
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    expected_status: int | None = None
    response_contains: list[str] = Field(default_factory=list)
    operation: str | None = None
    status_code: str | None = None
    content_type: str = "application/json"
    sample_payload: Any = None


class ActionTargetConfig(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: ActionTargetKind
    target: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    min_severity: Severity = "warning"
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)
    format: AlertFormat = AlertFormat.MARKDOWN
    dry_run: bool = False
    github_repo: str | None = None
    github_token_env: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str = "Task"
    jira_email_env: str | None = None
    jira_token_env: str | None = None
    owner_mentions: dict[str, str] = Field(default_factory=dict)


class SourceConfig(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: SourceKind
    url: str = Field(min_length=1)
    description: str | None = None
    selector: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)
    schedule_interval_seconds: int | None = Field(default=None, ge=60, le=604800)
    alert_severity_threshold: Severity = "warning"
    vendor: VendorKind | None = None
    impact: ImpactMap = Field(default_factory=ImpactMap)
    suppression_rules: list[FindingRule] = Field(default_factory=list)
    baseline_rules: list[FindingRule] = Field(default_factory=list)
    focus_endpoints: list[str] = Field(default_factory=list)
    focus_schema_paths: list[str] = Field(default_factory=list)
    proof_checks: list[ProofCheckConfig] = Field(default_factory=list)
    action_target_names: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("name cannot be empty")
        return normalized

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("url cannot be empty")
        return normalized


class AlertSinkConfig(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: AlertSinkKind
    target: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    min_severity: Severity = "warning"
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)
    format: AlertFormat = AlertFormat.JSON


class SchedulerConfig(BaseModel):
    enabled: bool = False
    interval_seconds: int = Field(default=3600, ge=60, le=604800)
    run_on_startup: bool = True
    poll_seconds: float = Field(default=5.0, ge=1.0, le=300.0)


class DashboardConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)


class ProjectConfig(BaseModel):
    db_path: str = ".drift-sentinel/drift.db"
    sources: list[SourceConfig]
    alerts: list[AlertSinkConfig] = Field(default_factory=list)
    actions: list[ActionTargetConfig] = Field(default_factory=list)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)


class SnapshotEnvelope(BaseModel):
    source_name: str
    kind: SourceKind
    url: str
    fetched_at: datetime
    content_hash: str
    payload: dict[str, Any]

    @classmethod
    def create(
        cls,
        *,
        source_name: str,
        kind: SourceKind,
        url: str,
        content_hash: str,
        payload: dict[str, Any],
    ) -> "SnapshotEnvelope":
        return cls(
            source_name=source_name,
            kind=kind,
            url=url,
            fetched_at=datetime.now(timezone.utc),
            content_hash=content_hash,
            payload=payload,
        )


class SnapshotRecord(SnapshotEnvelope):
    id: int


class DriftFinding(BaseModel):
    severity: Severity
    code: str
    message: str
    urgency: Urgency | None = None
    due_at: datetime | None = None
    recommended_remediation: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class DeadlineInsight(BaseModel):
    title: str
    due_at: datetime
    urgency: Urgency
    description: str
    source_line: str


class DriftReport(BaseModel):
    source_name: str
    kind: SourceKind
    left_snapshot_id: int
    right_snapshot_id: int
    left_fetched_at: datetime
    right_fetched_at: datetime
    findings: list[DriftFinding]
    impact: ImpactMap = Field(default_factory=ImpactMap)
    deadlines: list[DeadlineInsight] = Field(default_factory=list)
    vendor: VendorKind | None = None
    recommended_actions: list[str] = Field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        buckets = {"breaking": 0, "warning": 0, "info": 0}
        for finding in self.findings:
            buckets[finding.severity] += 1
        return buckets


class ScanRunRecord(BaseModel):
    id: int
    source_name: str
    kind: SourceKind
    status: RunStatus
    triggered_by: str
    started_at: datetime
    completed_at: datetime
    snapshot_id: int | None = None
    previous_snapshot_id: int | None = None
    changed: bool = False
    content_hash: str | None = None
    findings: list[DriftFinding] = Field(default_factory=list)
    error_message: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        buckets = {"breaking": 0, "warning": 0, "info": 0}
        for finding in self.findings:
            buckets[finding.severity] += 1
        return buckets


class AlertDeliveryRecord(BaseModel):
    id: int
    scan_run_id: int
    source_name: str
    sink_name: str
    sink_kind: AlertSinkKind
    status: RunStatus
    delivered_at: datetime
    payload_format: AlertFormat
    error_message: str | None = None
    detail: str | None = None


class ProofExecutionRecord(BaseModel):
    id: int
    scan_run_id: int
    source_name: str
    proof_name: str
    proof_kind: ProofCheckKind
    status: RunStatus
    executed_at: datetime
    detail: str | None = None
    error_message: str | None = None


class ActionExecutionRecord(BaseModel):
    id: int
    scan_run_id: int
    source_name: str
    target_name: str
    target_kind: ActionTargetKind
    status: RunStatus
    executed_at: datetime
    external_id: str | None = None
    detail: str | None = None
    error_message: str | None = None


class TimelineEventRecord(BaseModel):
    id: int
    source_name: str
    event_kind: TimelineEventKind
    created_at: datetime
    actor: str
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    scan_run_id: int | None = None


class SourceScanResult(BaseModel):
    source: SourceConfig
    run: ScanRunRecord
    current_snapshot: SnapshotRecord | None = None
    previous_snapshot: SnapshotRecord | None = None
    report: DriftReport | None = None
    alert_deliveries: list[AlertDeliveryRecord] = Field(default_factory=list)
    proof_executions: list[ProofExecutionRecord] = Field(default_factory=list)
    action_executions: list[ActionExecutionRecord] = Field(default_factory=list)
    timeline_events: list[TimelineEventRecord] = Field(default_factory=list)


def severity_rank(severity: Severity) -> int:
    return {"info": 0, "warning": 1, "breaking": 2}[severity]


def severity_meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return severity_rank(severity) >= severity_rank(threshold)


def urgency_rank(urgency: Urgency) -> int:
    return {"none": 0, "future": 1, "upcoming": 2, "soon": 3, "immediate": 4, "overdue": 5}[urgency]
