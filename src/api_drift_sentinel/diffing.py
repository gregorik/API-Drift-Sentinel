from __future__ import annotations

from difflib import unified_diff
from typing import Any, Literal

from api_drift_sentinel.models import DriftFinding, SourceKind

SchemaMode = Literal["request", "response"]


def diff_payloads(
    *, kind: SourceKind, left: dict[str, Any], right: dict[str, Any]
) -> list[DriftFinding]:
    if kind == SourceKind.OPENAPI:
        return diff_openapi_payloads(left, right)
    return diff_html_payloads(left, right)


def diff_openapi_payloads(left: dict[str, Any], right: dict[str, Any]) -> list[DriftFinding]:
    findings: list[DriftFinding] = []

    left_version = left.get("info", {}).get("version")
    right_version = right.get("info", {}).get("version")
    if left_version != right_version:
        findings.append(
            DriftFinding(
                severity="info",
                code="spec-version-changed",
                message=f"Spec version changed from {left_version!r} to {right_version!r}.",
            )
        )

    left_operations = {item["key"]: item for item in left.get("operations", [])}
    right_operations = {item["key"]: item for item in right.get("operations", [])}

    for key in sorted(left_operations.keys() - right_operations.keys()):
        findings.append(
            DriftFinding(
                severity="breaking",
                code="operation-removed",
                message=f"Operation removed: {key}.",
                context={"operation": key},
            )
        )

    for key in sorted(right_operations.keys() - left_operations.keys()):
        findings.append(
            DriftFinding(
                severity="info",
                code="operation-added",
                message=f"Operation added: {key}.",
                context={"operation": key},
            )
        )

    for key in sorted(left_operations.keys() & right_operations.keys()):
        findings.extend(_diff_operation(key, left_operations[key], right_operations[key]))

    return findings


def _diff_operation(
    operation_key: str, left: dict[str, Any], right: dict[str, Any]
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []

    if left.get("deprecated") != right.get("deprecated"):
        findings.append(
            DriftFinding(
                severity="warning" if right.get("deprecated") else "info",
                code="operation-deprecation-changed",
                message=(
                    f"Deprecation flag changed for {operation_key}: "
                    f"{left.get('deprecated')} -> {right.get('deprecated')}."
                ),
                context={"operation": operation_key},
            )
        )

    left_parameters = {
        (item.get("location"), item.get("name")): item for item in left.get("parameters", [])
    }
    right_parameters = {
        (item.get("location"), item.get("name")): item for item in right.get("parameters", [])
    }

    for key in sorted(left_parameters.keys() - right_parameters.keys()):
        location, name = key
        findings.append(
            DriftFinding(
                severity="warning",
                code="parameter-removed",
                message=f"Parameter removed from {operation_key}: {location}:{name}.",
                context={"operation": operation_key, "parameter": f"{location}:{name}"},
            )
        )

    for key in sorted(right_parameters.keys() - left_parameters.keys()):
        location, name = key
        parameter = right_parameters[key]
        findings.append(
            DriftFinding(
                severity="breaking" if parameter.get("required") else "info",
                code="parameter-added",
                message=(
                    f"Parameter added to {operation_key}: {location}:{name} "
                    f"(required={parameter.get('required')})."
                ),
                context={"operation": operation_key, "parameter": f"{location}:{name}"},
            )
        )

    for key in sorted(left_parameters.keys() & right_parameters.keys()):
        before = left_parameters[key]
        after = right_parameters[key]
        if before.get("required") != after.get("required"):
            findings.append(
                DriftFinding(
                    severity="breaking" if after.get("required") else "warning",
                    code="parameter-requiredness-changed",
                    message=(
                        f"Required flag changed for {operation_key} parameter "
                        f"{key[0]}:{key[1]}: {before.get('required')} -> {after.get('required')}."
                    ),
                    context={"operation": operation_key, "parameter": f"{key[0]}:{key[1]}"},
                )
            )
        if before.get("schema") != after.get("schema"):
            context = {
                "operation": operation_key,
                "parameter": f"{key[0]}:{key[1]}",
                "schema_path": f"parameter {key[0]}:{key[1]}",
            }
            findings.append(
                DriftFinding(
                    severity="warning",
                    code="parameter-schema-changed",
                    message=f"Schema changed for {operation_key} parameter {key[0]}:{key[1]}.",
                    context=context,
                )
            )
            findings.extend(
                _compare_schema(
                    before=before.get("schema"),
                    after=after.get("schema"),
                    path=f"parameter {key[0]}:{key[1]}",
                    mode="request",
                    base_context=context,
                )
            )

    findings.extend(
        _diff_request_body(operation_key, left.get("request_body", {}), right.get("request_body", {}))
    )
    findings.extend(_diff_responses(operation_key, left.get("responses", {}), right.get("responses", {})))

    return findings


def _diff_request_body(
    operation_key: str, left: dict[str, Any], right: dict[str, Any]
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    if left.get("required") != right.get("required"):
        findings.append(
            DriftFinding(
                severity="breaking" if right.get("required") else "warning",
                code="request-body-requiredness-changed",
                message=(
                    f"Request body required flag changed for {operation_key}: "
                    f"{left.get('required')} -> {right.get('required')}."
                ),
                context={"operation": operation_key},
            )
        )

    left_content = left.get("content", {})
    right_content = right.get("content", {})
    for content_type in sorted(left_content.keys() - right_content.keys()):
        findings.append(
            DriftFinding(
                severity="warning",
                code="request-body-content-removed",
                message=f"Request content type removed from {operation_key}: {content_type}.",
                context={"operation": operation_key, "content_type": content_type},
            )
        )
    for content_type in sorted(right_content.keys() - left_content.keys()):
        findings.append(
            DriftFinding(
                severity="info",
                code="request-body-content-added",
                message=f"Request content type added to {operation_key}: {content_type}.",
                context={"operation": operation_key, "content_type": content_type},
            )
        )
    for content_type in sorted(left_content.keys() & right_content.keys()):
        before_schema = left_content[content_type].get("schema")
        after_schema = right_content[content_type].get("schema")
        if before_schema != after_schema:
            context = {
                "operation": operation_key,
                "content_type": content_type,
                "schema_path": f"request body {content_type}",
            }
            findings.append(
                DriftFinding(
                    severity="warning",
                    code="request-body-schema-changed",
                    message=(
                        f"Request schema changed for {operation_key} content type {content_type}."
                    ),
                    context=context,
                )
            )
            findings.extend(
                _compare_schema(
                    before=before_schema,
                    after=after_schema,
                    path=f"request body {content_type}",
                    mode="request",
                    base_context=context,
                )
            )
    return findings


def _diff_responses(
    operation_key: str, left: dict[str, Any], right: dict[str, Any]
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    for status_code in sorted(left.keys() - right.keys()):
        findings.append(
            DriftFinding(
                severity="breaking",
                code="response-removed",
                message=f"Response removed from {operation_key}: {status_code}.",
                context={"operation": operation_key, "status_code": status_code},
            )
        )
    for status_code in sorted(right.keys() - left.keys()):
        findings.append(
            DriftFinding(
                severity="info",
                code="response-added",
                message=f"Response added to {operation_key}: {status_code}.",
                context={"operation": operation_key, "status_code": status_code},
            )
        )
    for status_code in sorted(left.keys() & right.keys()):
        left_response = left[status_code]
        right_response = right[status_code]
        left_content = left_response.get("content", {})
        right_content = right_response.get("content", {})
        if left_content != right_content:
            findings.append(
                DriftFinding(
                    severity="warning",
                    code="response-schema-changed",
                    message=f"Response schema changed for {operation_key}: {status_code}.",
                    context={"operation": operation_key, "status_code": status_code},
                )
            )

        for content_type in sorted(left_content.keys() - right_content.keys()):
            findings.append(
                DriftFinding(
                    severity="warning",
                    code="response-content-type-removed",
                    message=(
                        f"Response content type removed from {operation_key} "
                        f"status {status_code}: {content_type}."
                    ),
                    context={
                        "operation": operation_key,
                        "status_code": status_code,
                        "content_type": content_type,
                    },
                )
            )

        for content_type in sorted(right_content.keys() - left_content.keys()):
            findings.append(
                DriftFinding(
                    severity="info",
                    code="response-content-type-added",
                    message=(
                        f"Response content type added to {operation_key} "
                        f"status {status_code}: {content_type}."
                    ),
                    context={
                        "operation": operation_key,
                        "status_code": status_code,
                        "content_type": content_type,
                    },
                )
            )

        for content_type in sorted(left_content.keys() & right_content.keys()):
            findings.extend(
                _compare_schema(
                    before=left_content[content_type].get("schema"),
                    after=right_content[content_type].get("schema"),
                    path=f"response {status_code} {content_type}",
                    mode="response",
                    base_context={
                        "operation": operation_key,
                        "status_code": status_code,
                        "content_type": content_type,
                        "schema_path": f"response {status_code} {content_type}",
                    },
                )
            )

        findings.extend(
            _diff_response_headers(
                operation_key=operation_key,
                status_code=status_code,
                left=left_response.get("headers", {}),
                right=right_response.get("headers", {}),
            )
        )
    return findings


def _diff_response_headers(
    *, operation_key: str, status_code: str, left: dict[str, Any], right: dict[str, Any]
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    for header_name in sorted(left.keys() - right.keys()):
        findings.append(
            DriftFinding(
                severity="warning",
                code="response-header-removed",
                message=(
                    f"Response header removed from {operation_key} status {status_code}: "
                    f"{header_name}."
                ),
                context={
                    "operation": operation_key,
                    "status_code": status_code,
                    "header": header_name,
                },
            )
        )
    for header_name in sorted(right.keys() - left.keys()):
        findings.append(
            DriftFinding(
                severity="info",
                code="response-header-added",
                message=(
                    f"Response header added to {operation_key} status {status_code}: "
                    f"{header_name}."
                ),
                context={
                    "operation": operation_key,
                    "status_code": status_code,
                    "header": header_name,
                },
            )
        )
    for header_name in sorted(left.keys() & right.keys()):
        before = left[header_name]
        after = right[header_name]
        if before.get("schema") != after.get("schema"):
            findings.extend(
                _compare_schema(
                    before=before.get("schema"),
                    after=after.get("schema"),
                    path=f"response header {status_code} {header_name}",
                    mode="response",
                    base_context={
                        "operation": operation_key,
                        "status_code": status_code,
                        "header": header_name,
                        "schema_path": f"response header {status_code} {header_name}",
                    },
                )
            )
    return findings


def _compare_schema(
    *,
    before: Any,
    after: Any,
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    if before == after:
        return []

    findings: list[DriftFinding] = []
    if before is None or after is None:
        findings.append(
            DriftFinding(
                severity="warning",
                code=f"{mode}-schema-presence-changed",
                message=f"{_mode_label(mode)} schema presence changed at {path}.",
                context=base_context,
            )
        )
        return findings

    if not isinstance(before, dict) or not isinstance(after, dict):
        findings.append(
            DriftFinding(
                severity="breaking" if mode == "request" else "warning",
                code=f"{mode}-schema-structure-changed",
                message=f"{_mode_label(mode)} schema structure changed at {path}.",
                context=base_context,
            )
        )
        return findings

    if any(key in before or key in after for key in ("oneOf", "anyOf", "allOf")):
        if before.get("oneOf") != after.get("oneOf") or before.get("anyOf") != after.get(
            "anyOf"
        ) or before.get("allOf") != after.get("allOf"):
            findings.append(
                DriftFinding(
                    severity="warning",
                    code=f"{mode}-composite-schema-changed",
                    message=f"{_mode_label(mode)} composite schema changed at {path}.",
                    context=base_context,
                )
            )

    findings.extend(_compare_type_sets(before, after, path, mode, base_context))
    findings.extend(_compare_nullable(before, after, path, mode, base_context))
    findings.extend(_compare_enums(before, after, path, mode, base_context))
    findings.extend(_compare_string_and_numeric_constraints(before, after, path, mode, base_context))
    findings.extend(_compare_object_shape(before, after, path, mode, base_context))
    findings.extend(_compare_array_shape(before, after, path, mode, base_context))
    findings.extend(_compare_additional_properties(before, after, path, mode, base_context))

    if before.get("format") != after.get("format"):
        findings.append(
            DriftFinding(
                severity="warning",
                code=f"{mode}-format-changed",
                message=(
                    f"{_mode_label(mode)} schema format changed at {path}: "
                    f"{before.get('format')!r} -> {after.get('format')!r}."
                ),
                context=base_context,
            )
        )

    if before.get("pattern") != after.get("pattern") and before.get("pattern") and after.get("pattern"):
        findings.append(
            DriftFinding(
                severity="breaking" if mode == "request" else "warning",
                code=f"{mode}-pattern-changed",
                message=f"{_mode_label(mode)} schema pattern changed at {path}.",
                context=base_context,
            )
        )

    return findings


def _compare_type_sets(
    before: dict[str, Any],
    after: dict[str, Any],
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    before_types = _type_set(before)
    after_types = _type_set(after)
    if not before_types or not after_types or before_types == after_types:
        return []

    if mode == "request":
        if not before_types.issubset(after_types):
            severity = "breaking"
            code = "request-type-narrowed"
            message = (
                f"Request schema became more restrictive at {path}: "
                f"{sorted(before_types)} -> {sorted(after_types)}."
            )
        else:
            severity = "info"
            code = "request-type-widened"
            message = (
                f"Request schema accepts additional types at {path}: "
                f"{sorted(before_types)} -> {sorted(after_types)}."
            )
    else:
        if not after_types.issubset(before_types):
            severity = "breaking"
            code = "response-type-widened"
            message = (
                f"Response schema widened at {path}: "
                f"{sorted(before_types)} -> {sorted(after_types)}."
            )
        else:
            severity = "info"
            code = "response-type-narrowed"
            message = (
                f"Response schema narrowed at {path}: "
                f"{sorted(before_types)} -> {sorted(after_types)}."
            )

    return [DriftFinding(severity=severity, code=code, message=message, context=base_context)]


def _compare_nullable(
    before: dict[str, Any],
    after: dict[str, Any],
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    before_nullable = bool(before.get("nullable", False))
    after_nullable = bool(after.get("nullable", False))
    if before_nullable == after_nullable:
        return []
    if mode == "request":
        severity = "breaking" if before_nullable and not after_nullable else "info"
        code = (
            "request-nullability-narrowed" if severity == "breaking" else "request-nullability-widened"
        )
    else:
        severity = "warning" if not before_nullable and after_nullable else "info"
        code = (
            "response-nullability-widened" if severity == "warning" else "response-nullability-narrowed"
        )
    return [
        DriftFinding(
            severity=severity,
            code=code,
            message=(
                f"{_mode_label(mode)} schema nullability changed at {path}: "
                f"{before_nullable} -> {after_nullable}."
            ),
            context=base_context,
        )
    ]


def _compare_enums(
    before: dict[str, Any],
    after: dict[str, Any],
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    before_enum = before.get("enum")
    after_enum = after.get("enum")
    if before_enum == after_enum or (before_enum is None and after_enum is None):
        return []

    before_set = set(_normalize_enum_values(before_enum))
    after_set = set(_normalize_enum_values(after_enum))

    if mode == "request":
        if before_enum is None and after_enum is not None:
            severity = "breaking"
            code = "request-enum-introduced"
            message = f"Request schema introduced an enum restriction at {path}."
        elif before_enum is not None and after_enum is None:
            severity = "info"
            code = "request-enum-removed"
            message = f"Request schema removed an enum restriction at {path}."
        elif not before_set.issubset(after_set):
            severity = "breaking"
            code = "request-enum-narrowed"
            message = f"Request schema enum narrowed at {path}."
        else:
            severity = "info"
            code = "request-enum-expanded"
            message = f"Request schema enum expanded at {path}."
    else:
        if before_enum is None and after_enum is not None:
            severity = "info"
            code = "response-enum-introduced"
            message = f"Response schema narrowed to an enum at {path}."
        elif before_enum is not None and after_enum is None:
            severity = "warning"
            code = "response-enum-removed"
            message = f"Response schema removed an enum guarantee at {path}."
        elif not after_set.issubset(before_set):
            severity = "breaking"
            code = "response-enum-expanded"
            message = f"Response schema enum expanded at {path}."
        else:
            severity = "info"
            code = "response-enum-narrowed"
            message = f"Response schema enum narrowed at {path}."

    return [DriftFinding(severity=severity, code=code, message=message, context=base_context)]


def _compare_string_and_numeric_constraints(
    before: dict[str, Any],
    after: dict[str, Any],
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    for key, direction in (
        ("minimum", "lower-bound"),
        ("minLength", "lower-bound"),
        ("minItems", "lower-bound"),
        ("minProperties", "lower-bound"),
        ("maximum", "upper-bound"),
        ("maxLength", "upper-bound"),
        ("maxItems", "upper-bound"),
        ("maxProperties", "upper-bound"),
    ):
        before_value = before.get(key)
        after_value = after.get(key)
        if before_value == after_value or before_value is None or after_value is None:
            continue
        became_stricter = after_value > before_value if direction == "lower-bound" else after_value < before_value

        if mode == "request":
            severity = "breaking" if became_stricter else "info"
        else:
            severity = "warning" if not became_stricter else "info"

        findings.append(
            DriftFinding(
                severity=severity,
                code=f"{mode}-{key}-changed",
                message=(
                    f"{_mode_label(mode)} schema constraint {key} changed at {path}: "
                    f"{before_value} -> {after_value}."
                ),
                context=base_context,
            )
        )
    return findings


def _compare_object_shape(
    before: dict[str, Any],
    after: dict[str, Any],
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    before_props = before.get("properties", {})
    after_props = after.get("properties", {})
    if not isinstance(before_props, dict) or not isinstance(after_props, dict):
        return []

    findings: list[DriftFinding] = []
    before_required = set(before.get("required", []))
    after_required = set(after.get("required", []))

    if mode == "request":
        for prop in sorted(after_required - before_required):
            findings.append(
                DriftFinding(
                    severity="breaking",
                    code="request-required-property-added",
                    message=f"Request schema added required property {path}.{prop}.",
                    context={**base_context, "schema_path": f"{path}.{prop}"},
                )
            )
        for prop in sorted(before_required - after_required):
            findings.append(
                DriftFinding(
                    severity="info",
                    code="request-required-property-removed",
                    message=f"Request schema made property optional at {path}.{prop}.",
                    context={**base_context, "schema_path": f"{path}.{prop}"},
                )
            )
    else:
        for prop in sorted(before_required - after_required):
            findings.append(
                DriftFinding(
                    severity="breaking",
                    code="response-required-property-removed",
                    message=f"Response schema no longer guarantees required property {path}.{prop}.",
                    context={**base_context, "schema_path": f"{path}.{prop}"},
                )
            )
        for prop in sorted(after_required - before_required):
            findings.append(
                DriftFinding(
                    severity="info",
                    code="response-required-property-added",
                    message=f"Response schema now always includes property {path}.{prop}.",
                    context={**base_context, "schema_path": f"{path}.{prop}"},
                )
            )

    for prop in sorted(before_props.keys() - after_props.keys()):
        severity = "warning"
        code = "request-property-removed"
        message = f"Request schema removed property {path}.{prop}."
        if mode == "response":
            severity = "breaking" if prop in before_required else "warning"
            code = "response-property-removed"
            message = f"Response schema removed property {path}.{prop}."
        findings.append(
            DriftFinding(
                severity=severity,
                code=code,
                message=message,
                context={**base_context, "schema_path": f"{path}.{prop}"},
            )
        )

    for prop in sorted(after_props.keys() - before_props.keys()):
        if mode == "request":
            severity = "breaking" if prop in after_required else "info"
            code = "request-property-added"
            message = f"Request schema added property {path}.{prop}."
        else:
            severity = "info"
            code = "response-property-added"
            message = f"Response schema added property {path}.{prop}."
        findings.append(
            DriftFinding(
                severity=severity,
                code=code,
                message=message,
                context={**base_context, "schema_path": f"{path}.{prop}"},
            )
        )

    for prop in sorted(before_props.keys() & after_props.keys()):
        findings.extend(
            _compare_schema(
                before=before_props[prop],
                after=after_props[prop],
                path=f"{path}.{prop}",
                mode=mode,
                base_context={**base_context, "schema_path": f"{path}.{prop}"},
            )
        )
    return findings


def _compare_array_shape(
    before: dict[str, Any],
    after: dict[str, Any],
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    before_items = before.get("items")
    after_items = after.get("items")
    if before_items == after_items or before_items is None or after_items is None:
        return []
    return _compare_schema(
        before=before_items,
        after=after_items,
        path=f"{path}[]",
        mode=mode,
        base_context={**base_context, "schema_path": f"{path}[]"},
    )


def _compare_additional_properties(
    before: dict[str, Any],
    after: dict[str, Any],
    path: str,
    mode: SchemaMode,
    base_context: dict[str, Any],
) -> list[DriftFinding]:
    before_value = before.get("additionalProperties")
    after_value = after.get("additionalProperties")
    if before_value == after_value or before_value is None or after_value is None:
        return []

    if isinstance(before_value, bool) and isinstance(after_value, bool):
        if mode == "request":
            severity = "breaking" if before_value and not after_value else "info"
            code = (
                "request-additional-properties-disabled"
                if severity == "breaking"
                else "request-additional-properties-enabled"
            )
        else:
            severity = "warning" if not before_value and after_value else "info"
            code = (
                "response-additional-properties-enabled"
                if severity == "warning"
                else "response-additional-properties-disabled"
            )
        return [
            DriftFinding(
                severity=severity,
                code=code,
                message=(
                    f"{_mode_label(mode)} schema additionalProperties changed at {path}: "
                    f"{before_value} -> {after_value}."
                ),
                context=base_context,
            )
        ]

    if isinstance(before_value, dict) and isinstance(after_value, dict):
        return _compare_schema(
            before=before_value,
            after=after_value,
            path=f"{path}.*",
            mode=mode,
            base_context={**base_context, "schema_path": f"{path}.*"},
        )
    return []


def diff_html_payloads(left: dict[str, Any], right: dict[str, Any]) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    if left.get("title") != right.get("title"):
        findings.append(
            DriftFinding(
                severity="warning",
                code="page-title-changed",
                message=f"Page title changed from {left.get('title')!r} to {right.get('title')!r}.",
            )
        )
    left_lines = left.get("lines", [])
    right_lines = right.get("lines", [])
    if left_lines != right_lines:
        excerpt = "\n".join(
            list(
                unified_diff(
                    left_lines,
                    right_lines,
                    fromfile="before",
                    tofile="after",
                    lineterm="",
                )
            )[:16]
        )
        findings.append(
            DriftFinding(
                severity="warning",
                code="page-content-changed",
                message="Page content changed.",
                context={"diff_excerpt": excerpt},
            )
        )
    return findings


def _type_set(schema: dict[str, Any]) -> set[str]:
    value = schema.get("type")
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    return {str(value)}


def _mode_label(mode: SchemaMode) -> str:
    return "Request" if mode == "request" else "Response"


def _normalize_enum_values(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [repr(item) for item in values]
