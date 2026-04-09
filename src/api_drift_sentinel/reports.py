from __future__ import annotations

import json

from api_drift_sentinel.models import DriftReport


def render_markdown(report: DriftReport) -> str:
    counts = report.counts
    lines = [
        f"# Drift Report: {report.source_name}",
        "",
        f"- Source kind: `{report.kind.value}`",
        f"- Vendor: `{report.vendor.value if report.vendor else 'unknown'}`",
        f"- Compare: snapshot `{report.left_snapshot_id}` -> `{report.right_snapshot_id}`",
        f"- Fetched at: `{report.left_fetched_at.isoformat()}` -> `{report.right_fetched_at.isoformat()}`",
        f"- Findings: breaking `{counts['breaking']}`, warning `{counts['warning']}`, info `{counts['info']}`",
        "",
    ]
    if report.impact.owners or report.impact.services or report.impact.repos:
        lines.extend(
            [
                "## Impact Map",
                "",
                f"- Owners: {', '.join(report.impact.owners) or '-'}",
                f"- Services: {', '.join(report.impact.services) or '-'}",
                f"- Repos: {', '.join(report.impact.repos) or '-'}",
                f"- Runbooks: {', '.join(report.impact.runbooks) or '-'}",
                f"- Customer workflows: {', '.join(report.impact.customer_workflows) or '-'}",
                "",
            ]
        )
    if report.deadlines:
        lines.extend(["## Deadlines", ""])
        for deadline in report.deadlines:
            lines.append(
                f"- [{deadline.urgency}] {deadline.title}: `{deadline.due_at.date().isoformat()}` {deadline.description}"
            )
        lines.append("")
    if report.recommended_actions:
        lines.extend(["## Recommended Actions", ""])
        for item in report.recommended_actions:
            lines.append(f"- {item}")
        lines.append("")
    if not report.findings:
        lines.append("No drift detected.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for finding in report.findings:
        suffix = ""
        if finding.urgency:
            suffix += f" urgency=`{finding.urgency}`"
        if finding.due_at:
            suffix += f" due=`{finding.due_at.date().isoformat()}`"
        lines.append(f"- [{finding.severity}] {finding.message}{suffix}")
        if finding.recommended_remediation:
            lines.append(f"  remediation: {finding.recommended_remediation}")
        diff_excerpt = finding.context.get("diff_excerpt")
        if diff_excerpt:
            lines.append("")
            lines.append("```diff")
            lines.append(diff_excerpt)
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def render_json(report: DriftReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2)
