"""Tests for YAML detection configuration."""

import pytest

from linuxtrace.detection.config import (
    DetectionConfig,
    load_detection_config,
)


def test_default_configuration():
    config = DetectionConfig()

    assert config.ssh_bruteforce.enabled is True
    assert config.ssh_bruteforce.threshold == 5
    assert config.ssh_success_after_failures.window_minutes == 5


def test_load_custom_configuration(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "version: 1\nssh_bruteforce:\n  enabled: true\n  threshold: 8\n  window_minutes: 10\n"
    )

    config = load_detection_config(path)

    assert config.ssh_bruteforce.threshold == 8
    assert config.ssh_bruteforce.window_minutes == 10


def test_disable_rule(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("version: 1\nssh_bruteforce:\n  enabled: false\n")

    config = load_detection_config(path)

    assert config.ssh_bruteforce.enabled is False


def test_reject_invalid_threshold(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("version: 1\nssh_bruteforce:\n  threshold: 0\n")

    with pytest.raises(ValueError):
        load_detection_config(path)


def test_reject_unknown_rule(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("version: 1\nunknown_rule:\n  enabled: true\n")

    with pytest.raises(ValueError):
        load_detection_config(path)


def test_reject_malformed_yaml(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("version: [invalid\n")

    with pytest.raises(ValueError):
        load_detection_config(path)


def test_reject_missing_version(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("ssh_bruteforce:\n  threshold: 5\n")

    with pytest.raises(ValueError):
        load_detection_config(path)


def test_reject_missing_file(tmp_path):
    with pytest.raises(ValueError):
        load_detection_config(tmp_path / "missing.yaml")
