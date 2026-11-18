from typer.testing import CliRunner

from linuxtrace.cli import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "LinuxTrace" in result.output
    assert "0.1.0" in result.output


def test_help_command():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "doctor" in result.output
    assert "version" in result.output


def test_doctor_command():
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "System Information" in result.output
    assert "Log Source Discovery" in result.output
    assert "Discovery Summary" in result.output
