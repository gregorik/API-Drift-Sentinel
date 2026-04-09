from __future__ import annotations

from pathlib import Path

import yaml

from api_drift_sentinel.models import ProjectConfig


def load_project_config(config_path: Path) -> ProjectConfig:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if raw is None:
        raise ValueError(f"Config file is empty: {config_path}")
    return ProjectConfig.model_validate(raw)
