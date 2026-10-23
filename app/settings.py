"""Load and validate config/settings.yaml. A bad file raises at import, so startup fails loudly."""
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.db import ROOT

SETTINGS_PATH = ROOT / "config" / "settings.yaml"


class SettingsError(Exception):
    """settings.yaml is missing, malformed or has a bad value."""


@dataclass(frozen=True)
class Settings:
    judge_block_score: int
    judge_approval_score: int
    judge_timeout_seconds: float
    fallback_approver: str


def load_settings(path=SETTINGS_PATH):
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise SettingsError(f"Cannot read {path}: {e}") from e
    if not isinstance(raw, dict):
        raise SettingsError("settings.yaml must be a mapping")
    try:
        s = Settings(
            judge_block_score=raw["judge_block_score"],
            judge_approval_score=raw["judge_approval_score"],
            judge_timeout_seconds=float(raw["judge_timeout_seconds"]),
            fallback_approver=raw["fallback_approver"],
        )
    except (KeyError, TypeError, ValueError) as e:
        raise SettingsError(f"Bad settings: {e!r}") from e

    for name in ("judge_block_score", "judge_approval_score"):
        value = getattr(s, name)
        if isinstance(value, bool) or not isinstance(value, int):
            raise SettingsError(f"{name} must be an integer")
    if not 0 < s.judge_approval_score < s.judge_block_score <= 100:
        raise SettingsError("Need 0 < judge_approval_score < judge_block_score <= 100")
    if s.judge_timeout_seconds <= 0:
        raise SettingsError("judge_timeout_seconds must be positive")
    if not isinstance(s.fallback_approver, str) or not s.fallback_approver:
        raise SettingsError("fallback_approver must be a user id")
    return s


SETTINGS = load_settings()
