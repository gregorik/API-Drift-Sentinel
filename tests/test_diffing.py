from pathlib import Path

from api_drift_sentinel.diffing import diff_html_payloads, diff_openapi_payloads
from api_drift_sentinel.fetchers import normalize_html_document, normalize_openapi_document


FIXTURES = Path(__file__).parent / "fixtures"


def test_openapi_diff_flags_breaking_changes() -> None:
    before = normalize_openapi_document((FIXTURES / "openapi_before.yaml").read_text(encoding="utf-8"))
    after = normalize_openapi_document((FIXTURES / "openapi_after.yaml").read_text(encoding="utf-8"))

    findings = diff_openapi_payloads(before, after)
    codes = {finding.code for finding in findings}
    messages = "\n".join(finding.message for finding in findings)

    assert "spec-version-changed" in codes
    assert "operation-removed" in codes
    assert "parameter-added" in codes
    assert "request-body-requiredness-changed" in codes
    assert "GET /orders/{order_id}" in messages
    assert "GET /orders" in messages


def test_html_diff_returns_excerpt() -> None:
    before = normalize_html_document((FIXTURES / "page_before.html").read_text(encoding="utf-8"))
    after = normalize_html_document((FIXTURES / "page_after.html").read_text(encoding="utf-8"))

    findings = diff_html_payloads(before, after)

    assert len(findings) == 1
    assert findings[0].code == "page-content-changed"
    assert "X-Webhook-Signature" in findings[0].context["diff_excerpt"]
