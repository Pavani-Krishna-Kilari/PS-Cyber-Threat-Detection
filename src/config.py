"""
Project configuration loader (shared by all phases).

Reads configs/config.yaml and fills in any missing key from DEFAULT_CONFIG,
so the pipeline still works if the file is missing or incomplete.
"""

import copy
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "config.yaml"

DEFAULT_CONFIG = {
    "paths": {"raw_dir": "data/raw", "interim_dir": "data/interim",
              "processed_dir": "data/processed", "reports_dir": "reports"},
    "dataset": {"name": "CICIDS2017", "raw_files": "auto", "encoding": "latin-1"},
    "labels": {"benign_label": "BENIGN", "attack_labels": ["FTP-Patator", "SSH-Patator"],
               "unknown_label_policy": "error"},
    "cleaning": {"non_finite_strategy": "drop_rows", "max_drop_fraction": 0.01,
                 "remove_duplicates": True, "duplicate_keep": "first",
                 "remove_constant_columns": True, "invalid_network_fields": "drop"},
    "timestamp": {"date_order": "auto", "expected_weekday": "auto",
                  "fallback_date_order": "day_first", "hour_correction": "auto",
                  "max_unparseable_fraction": 0.001},
    "features": {"context_columns": ["flow_id", "source_ip", "destination_ip", "source_port",
                                     "destination_port", "protocol", "timestamp"]},
    "split": {"enabled": True, "block_minutes": 20, "train_fraction": 0.70,
              "validation_fraction": 0.15, "test_fraction": 0.15, "random_seed": 42},
    "output": {"format": "csv", "float_dtype": "float32", "sample_rows": 1000},
    "window": {"size_seconds": 600, "step_seconds": 60},
    "models": {"default_model": "FCNN"},
}

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


class ConfigError(Exception):
    """Raised when the configuration is invalid."""


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _check_choice(cfg, section, key, choices):
    value = cfg[section][key]
    if value not in choices:
        raise ConfigError(f"config '{section}.{key}' = {value!r} is not valid. Allowed: {list(choices)}")


def validate_config(cfg: dict) -> None:
    _check_choice(cfg, "labels", "unknown_label_policy", ["error", "attack"])
    _check_choice(cfg, "cleaning", "non_finite_strategy", ["drop_rows", "keep_as_nan"])
    _check_choice(cfg, "cleaning", "duplicate_keep", ["first", "last"])
    _check_choice(cfg, "cleaning", "invalid_network_fields", ["drop", "error"])
    _check_choice(cfg, "timestamp", "date_order", ["auto", "day_first", "month_first"])
    _check_choice(cfg, "timestamp", "fallback_date_order", ["day_first", "month_first"])
    _check_choice(cfg, "timestamp", "hour_correction", ["auto", "always", "never"])
    _check_choice(cfg, "timestamp", "expected_weekday", ["auto", "none"] + WEEKDAYS)
    _check_choice(cfg, "output", "format", ["csv", "parquet"])
    _check_choice(cfg, "output", "float_dtype", ["float32", "float64"])
    if not cfg["labels"]["attack_labels"]:
        raise ConfigError("config 'labels.attack_labels' must list at least one attack label.")
    if not 0 <= cfg["cleaning"]["max_drop_fraction"] <= 1:
        raise ConfigError("config 'cleaning.max_drop_fraction' must be between 0 and 1.")
    s = cfg["split"]
    total = s["train_fraction"] + s["validation_fraction"] + s["test_fraction"]
    if abs(total - 1.0) > 1e-6:
        raise ConfigError(f"split fractions must add up to 1.0 (they add up to {total}).")
    if s["block_minutes"] <= 0:
        raise ConfigError("config 'split.block_minutes' must be > 0.")


def load_config(path=None):
    """Return (config_dict, human-readable description of where it came from)."""
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    if path.exists():
        try:
            import yaml
        except ImportError as e:
            raise ConfigError("PyYAML is not installed. Run: pip install -r requirements.txt") from e
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Could not read {path}: invalid YAML ({e})") from e
        cfg = _deep_merge(DEFAULT_CONFIG, user_cfg)
        source = f"{path} (missing keys filled from built-in defaults)"
    else:
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        source = f"built-in defaults ({path} not found)"
    validate_config(cfg)
    return cfg, source


def resolve_path(relative: str, root: Path = PROJECT_ROOT) -> Path:
    """Turn a config path such as 'data/raw' into an absolute path under the project root."""
    p = Path(relative)
    return p if p.is_absolute() else root / p


def get_soc_data_dir() -> Path:
    """
    Returns the base directory for mutable runtime data.
    When SOC_DATA_DIR is configured (e.g. /var/data on Render), uses that directory.
    Otherwise defaults to PROJECT_ROOT / "data".
    Safely creates the directory if it does not already exist.
    """
    soc_data = os.environ.get("SOC_DATA_DIR")
    if soc_data and soc_data.strip():
        d = Path(soc_data.strip()).resolve()
        d.mkdir(parents=True, exist_ok=True)
        return d
    d = PROJECT_ROOT / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d
