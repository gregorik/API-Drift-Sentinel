from pathlib import Path

import yaml
from typer.testing import CliRunner

from api_drift_sentinel.cli import app

runner = CliRunner()


def test_cli_scan_report_and_history(tmp_path: Path) -> None:
    source_path = tmp_path / "demo_openapi.yaml"
    before = (Path(__file__).parent / "fixtures" / "openapi_before.yaml").read_text(encoding="utf-8")
    after = (Path(__file__).parent / "fixtures" / "openapi_after.yaml").read_text(encoding="utf-8")
    source_path.write_text(before, encoding="utf-8")

    db_path = tmp_path / "drift.db"
    config_path = tmp_path / "sources.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "db_path": str(db_path),
                "sources": [
                    {
                        "name": "demo-orders-api",
                        "kind": "openapi",
                        "url": str(source_path),
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    first_scan = runner.invoke(app, ["scan", "--config", str(config_path)])
    assert first_scan.exit_code == 0
    assert "baseline snapshot stored" in first_scan.stdout

    source_path.write_text(after, encoding="utf-8")

    second_scan = runner.invoke(app, ["scan", "--config", str(config_path)])
    assert second_scan.exit_code == 0
    assert "changed, stored snapshot #2" in second_scan.stdout
    assert "breaking=" in second_scan.stdout

    history = runner.invoke(app, ["history", "--db", str(db_path), "--source", "demo-orders-api"])
    assert history.exit_code == 0
    assert "demo-orders-api" in history.stdout

    report = runner.invoke(app, ["report", "--db", str(db_path), "--source", "demo-orders-api"])
    assert report.exit_code == 0
    assert "Operation removed: GET /orders/{order_id}." in report.stdout
