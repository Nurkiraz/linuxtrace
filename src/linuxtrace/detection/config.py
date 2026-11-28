"""Validated YAML configuration for detection rules."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError


class DetectionRuleConfig(BaseModel):
    """Configuration for a single detection rule."""

    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool = True
    threshold: int = Field(default=5, ge=2, le=10000, strict=True)
    window_minutes: int = Field(default=5, ge=1, le=1440, strict=True)


class AuditCommandRuleConfig(BaseModel):
    """Configuration for command-pattern detection."""

    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool = True


class DetectionConfig(BaseModel):
    """Configuration for all supported detection rules."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1, le=1, strict=True)

    ssh_bruteforce: DetectionRuleConfig = Field(default_factory=DetectionRuleConfig)
    ssh_success_after_failures: DetectionRuleConfig = Field(default_factory=DetectionRuleConfig)

    ssh_password_spraying: DetectionRuleConfig = Field(
        default_factory=lambda: DetectionRuleConfig(threshold=5, window_minutes=10)
    )

    audit_suspicious_commands: AuditCommandRuleConfig = Field(
        default_factory=AuditCommandRuleConfig
    )


def load_detection_config(path: Path) -> DetectionConfig:
    """Read and validate a local detection configuration."""

    path = Path(path)

    if not path.is_file():
        raise ValueError(f"Configuration file not found: {path}")

    if path.stat().st_size > 65536:
        raise ValueError("Configuration file exceeds 64 KiB")

    try:
        with path.open("r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Invalid YAML configuration: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Detection configuration must be a YAML mapping")

    if "version" not in data:
        raise ValueError("Detection configuration version is required")

    try:
        return DetectionConfig.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid detection configuration: {exc}") from exc
