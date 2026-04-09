from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlparse

from api_drift_sentinel.models import (
    DeadlineInsight,
    DriftFinding,
    DriftReport,
    FindingRule,
    SourceConfig,
    Urgency,
    VendorKind,
    severity_rank,
    urgency_rank,
)

ISO_DATE_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
LONG_DATE_RE = re.compile(
    r"\b("
    r"January|February|March|April|May|June|July|August|September|October|November|December"
    r")\s+(\d{1,2}),\s*(20\d{2})\b"
)
DEADLINE_KEYWORDS = ("deprecat", "sunset", "migrat", "effective", "before", "remov", "deadline")


def infer_vendor(source: SourceConfig) -> VendorKind:
    if source.vendor is not None:
        return source.vendor
    hostname = urlparse(source.url).netloc.lower()
    if "github" in hostname:
        return VendorKind.GITHUB
    if "monday" in hostname:
        return VendorKind.MONDAY
    if "shopify" in hostname:
        return VendorKind.SHOPIFY
    if "stripe" in hostname:
        return VendorKind.STRIPE
    if "slack" in hostname:
        return VendorKind.SLACK
    if "openai" in hostname:
        return VendorKind.OPENAI
    return VendorKind.GENERIC


def build_report(
    *,
    source: SourceConfig,
    left_snapshot_id: int,
    right_snapshot_id: int,
    left_fetched_at: datetime,
    right_fetched_at: datetime,
    findings: list[DriftFinding],
    current_payload: dict,
) -> DriftReport:
    vendor = infer_vendor(source)
    deadlines = extract_deadlines(source, current_payload)
    enriched = [enrich_finding(source, finding, vendor=vendor) for finding in findings]
    enriched.extend(deadline_findings(source, deadlines, vendor=vendor))
    controlled = apply_finding_controls(source, enriched)
    controlled.sort(key=_finding_sort_key, reverse=True)
    return DriftReport(
        source_name=source.name,
        kind=source.kind,
        left_snapshot_id=left_snapshot_id,
        right_snapshot_id=right_snapshot_id,
        left_fetched_at=left_fetched_at,
        right_fetched_at=right_fetched_at,
        findings=controlled,
        impact=source.impact,
        deadlines=sorted(deadlines, key=lambda item: (item.due_at, item.title)),
        vendor=vendor,
        recommended_actions=recommended_actions(source, controlled, deadlines, vendor),
    )


def apply_finding_controls(source: SourceConfig, findings: list[DriftFinding]) -> list[DriftFinding]:
    filtered: list[DriftFinding] = []
    for finding in findings:
        if not _matches_focus(source, finding):
            continue
        if _matches_rule(source.suppression_rules, finding):
            continue
        baseline = _matching_rule(source.baseline_rules, finding)
        if baseline is not None and finding.severity != "info":
            finding = finding.model_copy(
                update={
                    "severity": "info",
                    "message": f"{finding.message} Baselined by {baseline.name}.",
                    "context": {**finding.context, "baseline_rule": baseline.name},
                }
            )
        filtered.append(finding)
    return filtered


def enrich_finding(source: SourceConfig, finding: DriftFinding, *, vendor: VendorKind) -> DriftFinding:
    remediation = remediation_for_finding(source, finding, vendor=vendor)
    if remediation is None:
        return finding
    return finding.model_copy(update={"recommended_remediation": remediation})


def extract_deadlines(source: SourceConfig, payload: dict) -> list[DeadlineInsight]:
    lines = payload.get("lines", [])
    if not isinstance(lines, list):
        return []
    vendor = infer_vendor(source)
    insights = _extract_vendor_deadlines(vendor, lines)
    insights.extend(_extract_generic_deadlines(lines))
    deduped: dict[tuple[str, str], DeadlineInsight] = {}
    for item in insights:
        deduped[(item.title, item.due_at.isoformat())] = item
    return list(deduped.values())


def deadline_findings(
    source: SourceConfig, deadlines: list[DeadlineInsight], *, vendor: VendorKind
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    for deadline in deadlines:
        severity = _severity_for_urgency(deadline.urgency)
        findings.append(
            DriftFinding(
                severity=severity,
                code="deadline-detected",
                message=f"{deadline.title} due {deadline.due_at.date().isoformat()}: {deadline.description}",
                urgency=deadline.urgency,
                due_at=deadline.due_at,
                recommended_remediation=deadline_remediation(source, deadline, vendor=vendor),
                context={"source_line": deadline.source_line, "deadline_type": deadline.title},
            )
        )
    return findings


def remediation_for_finding(
    source: SourceConfig, finding: DriftFinding, *, vendor: VendorKind
) -> str | None:
    operation = finding.context.get("operation")
    runbook = source.impact.runbooks[0] if source.impact.runbooks else None
    owner_text = ", ".join(source.impact.owners) if source.impact.owners else "assigned owners"
    repo_text = ", ".join(source.impact.repos) if source.impact.repos else "dependent repos"
    workflow_text = (
        f" Validate customer workflows: {', '.join(source.impact.customer_workflows)}."
        if source.impact.customer_workflows
        else ""
    )

    if finding.code in {"operation-removed", "response-required-property-removed", "request-required-property-added"}:
        base = f"Review {repo_text} and impacted services with {owner_text}"
        if operation:
            base += f" for {operation}"
        if runbook:
            base += f"; follow runbook {runbook}"
        return base + "." + workflow_text
    if finding.code == "deadline-detected":
        return deadline_remediation(source, DeadlineInsight(
            title=str(finding.context.get("deadline_type", "Deadline")),
            due_at=finding.due_at or datetime.now(UTC),
            urgency=finding.urgency or "none",
            description=finding.message,
            source_line=str(finding.context.get("source_line", "")),
        ), vendor=vendor)
    if vendor == VendorKind.GITHUB and "deprecation" in finding.code:
        return "Review upstream GitHub migration notes and update affected GraphQL or REST clients before the published breaking-change date."
    if vendor == VendorKind.MONDAY:
        return "Check pinned monday API versions, update version headers, and verify integrations against the next quarterly release."
    if finding.severity == "breaking":
        return f"Escalate to {owner_text}, update clients in {repo_text}, and run smoke proofs before the next deployment." + workflow_text
    return None


def deadline_remediation(source: SourceConfig, deadline: DeadlineInsight, *, vendor: VendorKind) -> str:
    runbook = source.impact.runbooks[0] if source.impact.runbooks else "the relevant runbook"
    owners = ", ".join(source.impact.owners) if source.impact.owners else "source owners"
    if vendor == VendorKind.GITHUB:
        return f"Review GitHub breaking-change notes, assign {owners}, and execute {runbook} before {deadline.due_at.date().isoformat()}."
    if vendor == VendorKind.MONDAY:
        return f"Plan monday API version migration with {owners}, update version headers, and execute {runbook} before {deadline.due_at.date().isoformat()}."
    return f"Assign {owners}, update impacted integrations, and execute {runbook} before {deadline.due_at.date().isoformat()}."


def recommended_actions(
    source: SourceConfig,
    findings: list[DriftFinding],
    deadlines: list[DeadlineInsight],
    vendor: VendorKind,
) -> list[str]:
    actions: list[str] = []
    if source.impact.owners:
        actions.append(f"Notify owners: {', '.join(source.impact.owners)}.")
    if source.impact.services:
        actions.append(f"Review impacted services: {', '.join(source.impact.services)}.")
    if source.impact.repos:
        actions.append(f"Check dependent repos: {', '.join(source.impact.repos)}.")
    if source.impact.customer_workflows:
        actions.append(
            f"Validate customer-facing workflows: {', '.join(source.impact.customer_workflows)}."
        )
    if deadlines:
        next_deadline = min(deadlines, key=lambda item: item.due_at)
        actions.append(
            f"Closest deadline: {next_deadline.title} on {next_deadline.due_at.date().isoformat()} ({next_deadline.urgency})."
        )
    if any(finding.severity == "breaking" for finding in findings):
        actions.append("Open routed remediation work immediately and block releases until proofs pass.")
    if vendor == VendorKind.OPENAI:
        actions.append("Revalidate model, schema, and tool assumptions against the current OpenAI API surface.")
    return actions


def _extract_vendor_deadlines(vendor: VendorKind, lines: list[str]) -> list[DeadlineInsight]:
    if vendor == VendorKind.GITHUB:
        return _extract_github_deadlines(lines)
    if vendor == VendorKind.MONDAY:
        return _extract_monday_deadlines(lines)
    return []


def _extract_github_deadlines(lines: list[str]) -> list[DeadlineInsight]:
    insights: list[DeadlineInsight] = []
    current_due_at: datetime | None = None
    for line in lines:
        lower = line.lower()
        if "changes scheduled for" in lower:
            due_at = _parse_first_date(line)
            if due_at is not None:
                current_due_at = due_at
        elif current_due_at is not None and ("remove" in lower or "deprecat" in lower or "will be" in lower):
            insights.append(
                DeadlineInsight(
                    title="GitHub scheduled breaking change",
                    due_at=current_due_at,
                    urgency=_urgency_for_date(current_due_at),
                    description=line,
                    source_line=line,
                )
            )
    return insights


def _extract_monday_deadlines(lines: list[str]) -> list[DeadlineInsight]:
    insights: list[DeadlineInsight] = []
    for line in lines:
        lower = line.lower()
        if "release candidate" in lower or "maintenance" in lower or "migrat" in lower:
            due_at = _parse_first_date(line)
            if due_at is None:
                continue
            insights.append(
                DeadlineInsight(
                    title="monday version lifecycle milestone",
                    due_at=due_at,
                    urgency=_urgency_for_date(due_at),
                    description=line,
                    source_line=line,
                )
            )
    return insights


def _extract_generic_deadlines(lines: list[str]) -> list[DeadlineInsight]:
    insights: list[DeadlineInsight] = []
    for line in lines:
        lower = line.lower()
        if not any(keyword in lower for keyword in DEADLINE_KEYWORDS):
            continue
        due_at = _parse_first_date(line)
        if due_at is None:
            continue
        insights.append(
            DeadlineInsight(
                title="Documentation deadline",
                due_at=due_at,
                urgency=_urgency_for_date(due_at),
                description=line,
                source_line=line,
            )
        )
    return insights


def _parse_first_date(text: str) -> datetime | None:
    iso_match = ISO_DATE_RE.search(text)
    if iso_match:
        return datetime.strptime(iso_match.group(1), "%Y-%m-%d").replace(tzinfo=UTC)
    long_match = LONG_DATE_RE.search(text)
    if long_match:
        return datetime.strptime(long_match.group(0), "%B %d, %Y").replace(tzinfo=UTC)
    return None


def _urgency_for_date(due_at: datetime) -> Urgency:
    delta_days = (due_at.date() - datetime.now(UTC).date()).days
    if delta_days < 0:
        return "overdue"
    if delta_days <= 7:
        return "immediate"
    if delta_days <= 30:
        return "soon"
    if delta_days <= 90:
        return "upcoming"
    return "future"


def _severity_for_urgency(urgency: Urgency) -> str:
    return {
        "overdue": "breaking",
        "immediate": "breaking",
        "soon": "warning",
        "upcoming": "warning",
        "future": "info",
        "none": "info",
    }[urgency]


def _matches_focus(source: SourceConfig, finding: DriftFinding) -> bool:
    if not source.focus_endpoints and not source.focus_schema_paths:
        return True
    operation = str(finding.context.get("operation", ""))
    schema_path = str(finding.context.get("schema_path", ""))
    endpoint_match = (
        not source.focus_endpoints
        or any(item in operation for item in source.focus_endpoints)
        or any(item in finding.message for item in source.focus_endpoints)
    )
    schema_match = (
        not source.focus_schema_paths
        or any(item in schema_path for item in source.focus_schema_paths)
        or any(item in finding.message for item in source.focus_schema_paths)
    )
    return endpoint_match and schema_match


def _matches_rule(rules: list[FindingRule], finding: DriftFinding) -> bool:
    return _matching_rule(rules, finding) is not None


def _matching_rule(rules: list[FindingRule], finding: DriftFinding) -> FindingRule | None:
    now = datetime.now(UTC)
    for rule in rules:
        if rule.until is not None and rule.until < now:
            continue
        if rule.min_severity is not None and severity_rank(finding.severity) < severity_rank(rule.min_severity):
            continue
        if rule.finding_codes and finding.code not in rule.finding_codes:
            continue
        operation = str(finding.context.get("operation", ""))
        schema_path = str(finding.context.get("schema_path", ""))
        if rule.operations and not any(item in operation for item in rule.operations):
            continue
        if rule.endpoints and not any(item in operation or item in finding.message for item in rule.endpoints):
            continue
        if rule.schema_paths and not any(item in schema_path for item in rule.schema_paths):
            continue
        return rule
    return None


def _finding_sort_key(finding: DriftFinding) -> tuple[int, int]:
    urgency = urgency_rank(finding.urgency or "none")
    severity = severity_rank(finding.severity)
    return urgency, severity
