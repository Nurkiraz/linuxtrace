"""Tests for detection rule management CLI."""

import json

from typer.testing import CliRunner

from linuxtrace.cli import app

runner = CliRunner()


def test_default_rule_catalog():
    result = runner.invoke(app, ["detect", "rules", "--json"])

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["total_rules"] == 4
    assert payload["enabled_rules"] == 4
    assert {rule["rule_id"] for rule in payload["rules"]} == {
        "LT-SSH-001",
        "LT-SSH-002",
        "LT-SSH-003",
        "LT-AUDIT-001",
    }


def test_custom_rule_configuration(tmp_path):
    config = tmp_path / "rules.yaml"
    config.write_text("version: 1\nssh_bruteforce:\n  enabled: false\n  threshold: 8\n")

    result = runner.invoke(
        app,
        ["detect", "rules", "--config", str(config), "--json"],
    )

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["enabled_rules"] == 3

    brute = next(rule for rule in payload["rules"] if rule["rule_id"] == "LT-SSH-001")

    assert brute["enabled"] is False
    assert brute["threshold"] == 8


def test_rules_text_output():
    result = runner.invoke(app, ["detect", "rules"])

    assert result.exit_code == 0, result.output
    assert "LT-SSH-001" in result.output
    assert "LT-SSH-002" in result.output


def test_missing_configuration(tmp_path):
    missing = tmp_path / "missing.yaml"

    result = runner.invoke(
        app,
        ["detect", "rules", "--config", str(missing)],
    )

    assert result.exit_code == 1
    assert not missing.exists()
