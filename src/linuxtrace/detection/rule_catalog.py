"""Catalog of supported security detection rules."""

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.registry import get_registered_rules


def list_detection_rules(config: DetectionConfig) -> list[dict]:
    """Combine registered rule metadata with configuration."""

    rules = []

    for rule in get_registered_rules():
        settings = getattr(config, rule.config_key)

        entry = {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "severity": rule.severity,
            "mitre_techniques": list(rule.mitre_techniques),
            "enabled": settings.enabled,
        }

        if rule.uses_window:
            entry["threshold"] = settings.threshold
            entry["window_minutes"] = settings.window_minutes

        rules.append(entry)

    return rules
