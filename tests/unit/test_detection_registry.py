"""Tests for the central detection rule registry."""

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.registry import get_registered_rules
from linuxtrace.detection.rule_catalog import list_detection_rules
from linuxtrace.detection.runner import run_ssh_detections


def test_registry_contains_both_ssh_rules():
    rule_ids = {rule.rule_id for rule in get_registered_rules()}

    assert rule_ids == {"LT-SSH-001", "LT-SSH-002", "LT-SSH-003", "LT-AUDIT-001"}


def test_rule_identifiers_are_unique():
    rules = get_registered_rules()
    ids = [rule.rule_id for rule in rules]

    assert len(ids) == len(set(ids))


def test_registry_configuration_keys_exist():
    config = DetectionConfig()

    for rule in get_registered_rules():
        assert hasattr(config, rule.config_key)
        assert callable(rule.detector)


def test_catalog_matches_registry():
    config = DetectionConfig()
    catalog = list_detection_rules(config)

    assert {item["rule_id"] for item in catalog} == {
        rule.rule_id for rule in get_registered_rules()
    }


def test_all_rules_disabled():
    config = DetectionConfig.model_validate(
        {
            "version": 1,
            "ssh_bruteforce": {"enabled": False},
            "ssh_success_after_failures": {"enabled": False},
        }
    )

    assert run_ssh_detections([], config=config) == []
