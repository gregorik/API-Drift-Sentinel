from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from typing import Any

import httpx

from api_drift_sentinel.models import (
    ProofCheckConfig,
    ProofCheckKind,
    ProofExecutionRecord,
    RunStatus,
    SourceConfig,
)
from api_drift_sentinel.storage import DriftRepository


class ProofRunner:
    def __init__(self, repository: DriftRepository) -> None:
        self.repository = repository

    def run(
        self,
        *,
        source: SourceConfig,
        scan_run_id: int,
        snapshot_payload: dict[str, Any],
    ) -> list[ProofExecutionRecord]:
        records: list[ProofExecutionRecord] = []
        for check in source.proof_checks:
            executed_at = datetime.now(UTC).isoformat()
            try:
                detail = self._execute_check(check, snapshot_payload)
                record = self.repository.record_proof_execution(
                    scan_run_id=scan_run_id,
                    source_name=source.name,
                    proof_name=check.name,
                    proof_kind=check.kind,
                    status=RunStatus.SUCCESS,
                    executed_at=executed_at,
                    detail=detail,
                )
            except Exception as exc:
                record = self.repository.record_proof_execution(
                    scan_run_id=scan_run_id,
                    source_name=source.name,
                    proof_name=check.name,
                    proof_kind=check.kind,
                    status=RunStatus.ERROR,
                    executed_at=executed_at,
                    error_message=str(exc),
                )
            records.append(record)
        return records

    def _execute_check(self, check: ProofCheckConfig, snapshot_payload: dict[str, Any]) -> str:
        if check.kind == ProofCheckKind.COMMAND:
            if not check.command:
                raise ValueError(f"Proof {check.name!r} requires a command")
            completed = subprocess.run(
                check.command,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "command failed")
            return completed.stdout.strip() or "command succeeded"

        if check.kind == ProofCheckKind.HTTP:
            if not check.url:
                raise ValueError(f"Proof {check.name!r} requires a URL")
            with httpx.Client(timeout=20.0, follow_redirects=True) as client:
                response = client.request(
                    check.method.upper(),
                    check.url,
                    headers=check.headers,
                    content=check.body.encode("utf-8") if check.body else None,
                )
            if check.expected_status is not None and response.status_code != check.expected_status:
                raise RuntimeError(
                    f"expected HTTP {check.expected_status}, got {response.status_code}"
                )
            text = response.text
            for needle in check.response_contains:
                if needle not in text:
                    raise RuntimeError(f"response did not contain expected text: {needle}")
            return f"http {response.status_code}"

        if check.kind == ProofCheckKind.SAMPLE_SCHEMA:
            if not check.operation:
                raise ValueError(f"Proof {check.name!r} requires an operation")
            operation = _find_operation(snapshot_payload, check.operation)
            if check.status_code:
                content = operation.get("responses", {}).get(check.status_code, {}).get("content", {})
                schema = content.get(check.content_type, {}).get("schema")
            else:
                content = operation.get("request_body", {}).get("content", {})
                schema = content.get(check.content_type, {}).get("schema")
            if schema is None:
                raise RuntimeError("schema not found for proof target")
            errors = validate_sample_against_schema(schema, check.sample_payload, "$")
            if errors:
                raise RuntimeError("; ".join(errors[:5]))
            return "sample matches schema"

        raise ValueError(f"Unsupported proof kind: {check.kind}")


def _find_operation(snapshot_payload: dict[str, Any], operation_key: str) -> dict[str, Any]:
    for operation in snapshot_payload.get("operations", []):
        if operation.get("key") == operation_key:
            return operation
    raise KeyError(f"Operation {operation_key!r} not found")


def validate_sample_against_schema(schema: Any, sample: Any, path: str) -> list[str]:
    if schema is None:
        return []
    if isinstance(schema, bool):
        return [] if schema else [f"{path}: schema forbids value"]
    if not isinstance(schema, dict):
        return []

    errors: list[str] = []
    schema_type = schema.get("type")
    nullable = bool(schema.get("nullable", False))
    if sample is None:
        return [] if nullable or schema_type in (None, "null") else [f"{path}: null is not allowed"]

    if schema_type == "object":
        if not isinstance(sample, dict):
            return [f"{path}: expected object"]
        required = set(schema.get("required", []))
        for item in required:
            if item not in sample:
                errors.append(f"{path}.{item}: missing required property")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in sample.items():
            if key in properties:
                errors.extend(validate_sample_against_schema(properties[key], value, f"{path}.{key}"))
            elif additional is False:
                errors.append(f"{path}.{key}: additional property not allowed")
            elif isinstance(additional, dict):
                errors.extend(validate_sample_against_schema(additional, value, f"{path}.{key}"))
        return errors

    if schema_type == "array":
        if not isinstance(sample, list):
            return [f"{path}: expected array"]
        item_schema = schema.get("items")
        for index, item in enumerate(sample):
            errors.extend(validate_sample_against_schema(item_schema, item, f"{path}[{index}]"))
        return errors

    if schema_type == "string" and not isinstance(sample, str):
        return [f"{path}: expected string"]
    if schema_type == "integer" and not isinstance(sample, int):
        return [f"{path}: expected integer"]
    if schema_type == "number" and not isinstance(sample, (int, float)):
        return [f"{path}: expected number"]
    if schema_type == "boolean" and not isinstance(sample, bool):
        return [f"{path}: expected boolean"]

    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and sample not in enum_values:
        errors.append(f"{path}: {json.dumps(sample)} is not in enum")
    return errors
