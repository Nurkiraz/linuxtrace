"""Integration tests for YAML-configured detection runs."""

import json

from test_detection_runner_cli import prepare_database
from typer.testing import CliRunner

from linuxtrace.cli import app

runner = CliRunner()


def invoke_run(db_path, config_path):
    return runner.invoke(
        app,
        [
            "detect",
            "run",
            "--db",
            str(db_path),
            "--config",
            str(config_path),
            "--json",
        ],
    )


def test_yaml_disables_bruteforce(tmp_path):
    db = tmp_path / "events.db"
    prepare_database(db)

    config = tmp_path / "rules.yaml"
    config.write_text("version: 1\nssh_bruteforce:\n  enabled: false\n")

    result = invoke_run(db, config)

    assert result.exit_code == 0, result.output

    findings = json.loads(result.output)["findings"]

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LT-SSH-002"


def test_yaml_disables_all_rules(tmp_path):
    db = tmp_path / "events.db"
    prepare_database(db)

    config = tmp_path / "rules.yaml"
    config.write_text(
        "version: 1\n"
        "ssh_bruteforce:\n"
        "  enabled: false\n"
        "ssh_success_after_failures:\n"
        "  enabled: false\n"
    )

    result = invoke_run(db, config)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["total_findings"] == 0


def test_yaml_independent_thresholds(tmp_path):
    db = tmp_path / "events.db"
    prepare_database(db)

    config = tmp_path / "rules.yaml"
    config.write_text(
        "version: 1\nssh_bruteforce:\n  threshold: 6\nssh_success_after_failures:\n  threshold: 5\n"
    )

    result = invoke_run(db, config)

    assert result.exit_code == 0, result.output

    findings = json.loads(result.output)["findings"]

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LT-SSH-002"


def test_invalid_yaml_rejected(tmp_path):
    db = tmp_path / "events.db"
    prepare_database(db)

    config = tmp_path / "rules.yaml"
    config.write_text("version: [invalid\n")

    result = invoke_run(db, config)

    assert result.exit_code == 1
    assert "Detection run failed" in result.output


def test_missing_config_does_not_create_file(tmp_path):
    db = tmp_path / "events.db"
    prepare_database(db)

    missing = tmp_path / "missing.yaml"
    result = invoke_run(db, missing)

    assert result.exit_code == 1
    assert not missing.exists()
