from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

import httpx
import yaml
from bs4 import BeautifulSoup

from api_drift_sentinel.models import SnapshotEnvelope, SourceConfig, SourceKind

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def fetch_snapshot(source: SourceConfig) -> SnapshotEnvelope:
    raw_text = _load_text(source)
    if source.kind == SourceKind.OPENAPI:
        payload = normalize_openapi_document(raw_text)
    else:
        payload = normalize_html_document(raw_text, selector=source.selector)
    content_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return SnapshotEnvelope.create(
        source_name=source.name,
        kind=source.kind,
        url=source.url,
        content_hash=content_hash,
        payload=payload,
    )


def _load_text(source: SourceConfig) -> str:
    parsed = urlparse(source.url)
    if parsed.scheme in ("http", "https"):
        with httpx.Client(timeout=source.timeout_seconds, follow_redirects=True) as client:
            response = client.get(source.url, headers=source.headers)
            response.raise_for_status()
            return response.text

    local_path = _resolve_local_path(source.url)
    return local_path.read_text(encoding="utf-8")


def _resolve_local_path(location: str) -> Path:
    parsed = urlparse(location)
    if parsed.scheme == "file":
        candidate = f"//{parsed.netloc}{parsed.path}" if parsed.netloc else parsed.path
        return Path(url2pathname(candidate))
    return Path(location)


def normalize_html_document(raw_text: str, selector: str | None = None) -> dict[str, Any]:
    soup = BeautifulSoup(raw_text, "html.parser")
    selected = soup.select_one(selector) if selector else None
    root = selected or soup.find("main") or soup.find("article") or soup.body or soup
    title = soup.title.string.strip() if soup.title and soup.title.string else "Untitled"
    lines: list[str] = []
    for block in root.find_all(["h1", "h2", "h3", "p", "li", "code", "pre"]):
        text = " ".join(block.get_text(" ", strip=True).split())
        if text:
            lines.append(text)
    deduped_lines = _dedupe_adjacent(lines)
    return {
        "title": title,
        "line_count": len(deduped_lines),
        "lines": deduped_lines,
    }


def normalize_openapi_document(raw_text: str) -> dict[str, Any]:
    document = yaml.safe_load(raw_text)
    if not isinstance(document, dict):
        raise ValueError("OpenAPI document did not parse into a mapping")
    if "paths" not in document:
        raise ValueError("OpenAPI document is missing a top-level 'paths' key")
    resolver = OpenAPIResolver(document)

    operations: list[dict[str, Any]] = []
    for path, path_item in sorted(document["paths"].items()):
        path_item = resolver.dereference(path_item)
        if not isinstance(path_item, dict):
            continue
        inherited_parameters = _normalize_parameters(path_item.get("parameters", []), resolver)
        for method in HTTP_METHODS:
            operation = resolver.dereference(path_item.get(method))
            if not isinstance(operation, dict):
                continue
            merged_parameters = _merge_parameters(
                inherited_parameters,
                _normalize_parameters(operation.get("parameters", []), resolver),
            )
            operations.append(
                {
                    "key": f"{method.upper()} {path}",
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary"),
                    "deprecated": bool(operation.get("deprecated", False)),
                    "parameters": merged_parameters,
                    "request_body": _normalize_request_body(operation.get("requestBody"), resolver),
                    "responses": _normalize_responses(operation.get("responses", {}), resolver),
                }
            )

    return {
        "spec_version": document.get("openapi") or document.get("swagger"),
        "info": {
            "title": _string_or_none(document.get("info", {}).get("title")),
            "version": _string_or_none(document.get("info", {}).get("version")),
        },
        "operations": operations,
    }


def _dedupe_adjacent(lines: list[str]) -> list[str]:
    deduped: list[str] = []
    for line in lines:
        if not deduped or deduped[-1] != line:
            deduped.append(line)
    return deduped


class OpenAPIResolver:
    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document

    def dereference(self, value: Any, seen: tuple[str, ...] = ()) -> Any:
        if isinstance(value, dict) and "$ref" in value:
            ref = str(value["$ref"])
            if ref in seen:
                return {"$ref": ref}
            resolved = self._resolve_reference(ref)
            if isinstance(resolved, dict):
                merged = {**resolved, **{key: item for key, item in value.items() if key != "$ref"}}
            else:
                merged = resolved
            return self.dereference(merged, seen + (ref,))
        return value

    def _resolve_reference(self, ref: str) -> Any:
        if not ref.startswith("#/"):
            return {"$ref": ref}
        current: Any = self.document
        for part in ref[2:].split("/"):
            token = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or token not in current:
                return {"$ref": ref}
            current = current[token]
        return current


def _normalize_parameters(parameters: list[Any], resolver: OpenAPIResolver) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for parameter in parameters:
        parameter = resolver.dereference(parameter)
        if not isinstance(parameter, dict):
            continue
        if "$ref" in parameter:
            normalized.append(
                {
                    "name": parameter["$ref"],
                    "location": "$ref",
                    "required": False,
                    "schema": {"$ref": parameter["$ref"]},
                }
            )
            continue
        normalized.append(
            {
                "name": _string_or_none(parameter.get("name")),
                "location": _string_or_none(parameter.get("in")),
                "required": bool(parameter.get("required", False)),
                "schema": _canonicalize_schema(parameter.get("schema"), resolver),
            }
        )
    normalized.sort(key=lambda item: (item["location"] or "", item["name"] or ""))
    return normalized


def _merge_parameters(
    inherited: list[dict[str, Any]], operation_level: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    merged: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    for parameter in inherited + operation_level:
        merged[(parameter["location"], parameter["name"])] = parameter
    return sorted(merged.values(), key=lambda item: (item["location"] or "", item["name"] or ""))


def _normalize_request_body(request_body: Any, resolver: OpenAPIResolver) -> dict[str, Any]:
    request_body = resolver.dereference(request_body)
    if not isinstance(request_body, dict):
        return {"required": False, "content": {}}
    if "$ref" in request_body:
        return {"required": False, "content": {"$ref": {"$ref": request_body["$ref"]}}}
    content = request_body.get("content", {})
    normalized_content: dict[str, dict[str, Any]] = {}
    if isinstance(content, dict):
        for content_type, content_item in sorted(content.items()):
            content_item = resolver.dereference(content_item)
            if not isinstance(content_item, dict):
                continue
            normalized_content[content_type] = {
                "schema": _canonicalize_schema(content_item.get("schema"), resolver)
            }
    return {
        "required": bool(request_body.get("required", False)),
        "content": normalized_content,
    }


def _normalize_responses(
    responses: Any, resolver: OpenAPIResolver
) -> dict[str, dict[str, Any]]:
    if not isinstance(responses, dict):
        return {}
    normalized: dict[str, dict[str, Any]] = {}
    for status_code, response in sorted(responses.items()):
        response = resolver.dereference(response)
        if not isinstance(response, dict):
            continue
        if "$ref" in response:
            normalized[str(status_code)] = {"content": {"$ref": {"$ref": response["$ref"]}}}
            continue
        content = response.get("content", {})
        normalized_content: dict[str, dict[str, Any]] = {}
        if isinstance(content, dict):
            for content_type, content_item in sorted(content.items()):
                content_item = resolver.dereference(content_item)
                if not isinstance(content_item, dict):
                    continue
                normalized_content[content_type] = {
                    "schema": _canonicalize_schema(content_item.get("schema"), resolver)
                }
        headers = response.get("headers", {})
        normalized_headers: dict[str, dict[str, Any]] = {}
        if isinstance(headers, dict):
            for header_name, header in sorted(headers.items()):
                header = resolver.dereference(header)
                if not isinstance(header, dict):
                    continue
                normalized_headers[header_name] = {
                    "required": bool(header.get("required", False)),
                    "schema": _canonicalize_schema(header.get("schema"), resolver),
                }
        normalized[str(status_code)] = {
            "content": normalized_content,
            "headers": normalized_headers,
        }
    return normalized


def _canonicalize_schema(
    schema: Any, resolver: OpenAPIResolver, seen: tuple[str, ...] = ()
) -> Any:
    if schema is None:
        return None
    if isinstance(schema, dict) and "$ref" in schema:
        ref = str(schema["$ref"])
        if ref in seen:
            return {"$ref": ref}
        resolved = resolver._resolve_reference(ref)
        if isinstance(resolved, dict):
            merged = {**resolved, **{key: item for key, item in schema.items() if key != "$ref"}}
        else:
            merged = resolved
        return _canonicalize_schema(merged, resolver, seen + (ref,))
    if isinstance(schema, bool):
        return schema
    if isinstance(schema, list):
        return [_canonicalize_schema(item, resolver, seen) for item in schema]
    if not isinstance(schema, dict):
        return schema
    canonical: dict[str, Any] = {}
    schema_type = schema.get("type")
    if schema_type is None and isinstance(schema.get("properties"), dict):
        schema_type = "object"
    if schema_type is None and "items" in schema:
        schema_type = "array"
    if schema_type is not None:
        canonical["type"] = _normalize_type(schema_type)

    for key in (
        "format",
        "enum",
        "const",
        "required",
        "nullable",
        "description",
        "deprecated",
        "readOnly",
        "writeOnly",
        "default",
        "items",
        "properties",
        "additionalProperties",
        "oneOf",
        "anyOf",
        "allOf",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
    ):
        value = schema.get(key)
        if value is None:
            continue
        if key == "properties" and isinstance(value, dict):
            canonical[key] = {
                property_name: _canonicalize_schema(property_schema, resolver, seen)
                for property_name, property_schema in sorted(value.items())
            }
        elif key == "required" and isinstance(value, list):
            canonical[key] = sorted(str(item) for item in value)
        elif key == "enum" and isinstance(value, list):
            canonical[key] = sorted(value, key=_json_sort_key)
        elif key == "type":
            canonical[key] = _normalize_type(value)
        elif key == "additionalProperties":
            canonical[key] = (
                value
                if isinstance(value, bool)
                else _canonicalize_schema(value, resolver, seen)
            )
        else:
            canonical[key] = _canonicalize_schema(value, resolver, seen)
    return canonical


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _normalize_type(value: Any) -> str | list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    return str(value)


def _json_sort_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
