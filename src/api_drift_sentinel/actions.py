from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx

from api_drift_sentinel.models import (
    ActionExecutionRecord,
    ActionTargetConfig,
    ActionTargetKind,
    AlertFormat,
    RunStatus,
    SourceScanResult,
    severity_meets_threshold,
    severity_rank,
)
from api_drift_sentinel.reports import render_json, render_markdown
from api_drift_sentinel.storage import DriftRepository


class ActionDispatcher:
    def __init__(self, repository: DriftRepository) -> None:
        self.repository = repository

    def dispatch(
        self,
        result: SourceScanResult,
        targets: list[ActionTargetConfig],
    ) -> list[ActionExecutionRecord]:
        if result.report is None:
            return []
        failing_proofs = [item for item in result.proof_executions if item.status == RunStatus.ERROR]
        if not result.report.findings and not failing_proofs:
            return []

        records: list[ActionExecutionRecord] = []
        for target in targets:
            if not self._needs_action(result, target):
                continue
            executed_at = datetime.now(UTC).isoformat()
            try:
                external_id, detail = self._execute_target(target, result)
                record = self.repository.record_action_execution(
                    scan_run_id=result.run.id,
                    source_name=result.source.name,
                    target_name=target.name,
                    target_kind=target.kind,
                    status=RunStatus.SUCCESS,
                    executed_at=executed_at,
                    external_id=external_id,
                    detail=detail,
                )
            except Exception as exc:
                record = self.repository.record_action_execution(
                    scan_run_id=result.run.id,
                    source_name=result.source.name,
                    target_name=target.name,
                    target_kind=target.kind,
                    status=RunStatus.ERROR,
                    executed_at=executed_at,
                    error_message=str(exc),
                )
            records.append(record)
        return records

    def _needs_action(self, result: SourceScanResult, target: ActionTargetConfig) -> bool:
        for finding in result.report.findings:
            if severity_meets_threshold(finding.severity, target.min_severity):
                return True
        return any(item.status == RunStatus.ERROR for item in result.proof_executions)

    def _execute_target(
        self, target: ActionTargetConfig, result: SourceScanResult
    ) -> tuple[str | None, str]:
        payload = _render_payload(result, target.format, target.owner_mentions)
        title = _issue_title(result)
        if target.kind == ActionTargetKind.FILE:
            if target.target is None:
                raise ValueError(f"Action target {target.name!r} requires a file path")
            path = Path(target.target)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n\n")
            return None, str(path)

        if target.kind == ActionTargetKind.WEBHOOK:
            if target.target is None:
                raise ValueError(f"Action target {target.name!r} requires a webhook URL")
            body = _webhook_payload(result, payload, title)
            if target.dry_run:
                return None, f"dry-run webhook {json.dumps(body)[:400]}"
            with httpx.Client(timeout=target.timeout_seconds, follow_redirects=True) as client:
                response = client.post(target.target, headers=target.headers, json=body)
                response.raise_for_status()
            return None, f"webhook {response.status_code}"

        if target.kind == ActionTargetKind.SLACK_WEBHOOK:
            if target.target is None:
                raise ValueError(f"Action target {target.name!r} requires a Slack webhook URL")
            body = {"text": payload}
            if target.dry_run:
                return None, f"dry-run slack {json.dumps(body)[:400]}"
            with httpx.Client(timeout=target.timeout_seconds, follow_redirects=True) as client:
                response = client.post(target.target, headers=target.headers, json=body)
                response.raise_for_status()
            return None, f"slack {response.status_code}"

        if target.kind == ActionTargetKind.GITHUB_ISSUE:
            repo = target.github_repo or target.target
            if not repo:
                raise ValueError(f"Action target {target.name!r} requires github_repo or target")
            token = _resolve_secret(target.github_token_env)
            body = {"title": title, "body": payload}
            if target.dry_run:
                return None, f"dry-run github issue {json.dumps(body)[:400]}"
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                **target.headers,
            }
            url = f"https://api.github.com/repos/{repo}/issues"
            with httpx.Client(timeout=target.timeout_seconds, follow_redirects=True) as client:
                response = client.post(url, headers=headers, json=body)
                response.raise_for_status()
                issue = response.json()
            return str(issue.get("number")), issue.get("html_url", url)

        if target.kind == ActionTargetKind.JIRA_ISSUE:
            if target.target is None or target.jira_project_key is None:
                raise ValueError(
                    f"Action target {target.name!r} requires target and jira_project_key"
                )
            email = _resolve_secret(target.jira_email_env)
            token = _resolve_secret(target.jira_token_env)
            auth = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("ascii")
            body = {
                "fields": {
                    "project": {"key": target.jira_project_key},
                    "summary": title,
                    "description": payload,
                    "issuetype": {"name": target.jira_issue_type},
                }
            }
            if target.dry_run:
                return None, f"dry-run jira issue {json.dumps(body)[:400]}"
            headers = {
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                **target.headers,
            }
            url = target.target.rstrip("/") + "/rest/api/3/issue"
            with httpx.Client(timeout=target.timeout_seconds, follow_redirects=True) as client:
                response = client.post(url, headers=headers, json=body)
                response.raise_for_status()
                issue = response.json()
            return str(issue.get("key")), issue.get("self", url)

        raise ValueError(f"Unsupported action target kind: {target.kind}")


def _render_payload(
    result: SourceScanResult, format: AlertFormat, owner_mentions: dict[str, str]
) -> str:
    report = result.report
    assert report is not None
    proof_block = ""
    if result.proof_executions:
        lines = ["", "Proofs:"]
        for proof in result.proof_executions:
            status = proof.status.value
            detail = proof.detail or proof.error_message or ""
            lines.append(f"- {proof.proof_name}: {status} {detail}".strip())
        proof_block = "\n".join(lines)

    owner_block = ""
    if result.source.impact.owners:
        mentions = [owner_mentions.get(item, item) for item in result.source.impact.owners]
        owner_block = "\nOwners: " + ", ".join(mentions)

    if format == AlertFormat.JSON:
        base = report.model_dump(mode="json")
        base["proofs"] = [proof.model_dump(mode="json") for proof in result.proof_executions]
        return json.dumps(base, indent=2)
    return render_markdown(report) + owner_block + proof_block


def _webhook_payload(result: SourceScanResult, rendered: str, title: str) -> dict[str, object]:
    report = result.report
    assert report is not None
    return {
        "title": title,
        "source": result.source.name,
        "vendor": report.vendor.value if report.vendor else None,
        "impact": report.impact.model_dump(mode="json"),
        "recommended_actions": report.recommended_actions,
        "findings": [finding.model_dump(mode="json") for finding in report.findings],
        "proofs": [proof.model_dump(mode="json") for proof in result.proof_executions],
        "rendered": rendered,
    }


def _issue_title(result: SourceScanResult) -> str:
    report = result.report
    assert report is not None
    max_severity = max((severity_rank(item.severity) for item in report.findings), default=0)
    severity_label = {0: "info", 1: "warning", 2: "breaking"}[max_severity]
    return f"[api-drift][{severity_label}] {result.source.name} integration changes detected"


def _resolve_secret(env_name: str | None) -> str:
    if env_name is None:
        raise ValueError("Missing credential environment variable name")
    value = os.getenv(env_name)
    if not value:
        raise ValueError(f"Environment variable {env_name!r} is not set")
    return value
