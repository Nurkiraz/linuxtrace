from decimal import Decimal
from pathlib import Path

import pytest

from linuxtrace.parsers.audit import parse_audit_record

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/audit/var/log/audit/audit.log"


def load_records():
    return [parse_audit_record(line) for line in FIXTURE.read_text().splitlines()]


def test_audit_fixture_records():
    records = load_records()
    assert len(records) == 5
    assert all(record is not None for record in records)


def test_audit_record_types():
    records = load_records()
    assert [record.record_type for record in records] == [
        "SYSCALL",
        "EXECVE",
        "CWD",
        "PATH",
        "USER_LOGIN",
    ]


def test_related_audit_serials():
    records = load_records()
    assert all(record.serial == 450 for record in records[:4])
    assert records[4].serial == 451


def test_audit_timestamp_precision():
    record = load_records()[0]
    assert record.timestamp == Decimal("1794996001.123")


def test_syscall_fields():
    record = load_records()[0]
    assert record.fields["uid"] == "1000"
    assert record.fields["comm"] == "cat"
    assert record.fields["exe"] == "/usr/bin/cat"


def test_execve_arguments():
    record = load_records()[1]
    assert record.fields["argc"] == "2"
    assert record.fields["a0"] == "cat"
    assert record.fields["a1"] == "/etc/hosts"


def test_path_and_cwd():
    records = load_records()
    assert records[2].fields["cwd"] == "/home/analyst"
    assert records[3].fields["name"] == "/etc/hosts"


def test_optional_node():
    record = parse_audit_record("node=server1 type=SYSCALL msg=audit(1794996001.123:450): pid=100")
    assert record.node == "server1"


def test_invalid_header():
    assert parse_audit_record("not an audit record") is None


def test_invalid_quoted_value():
    with pytest.raises(ValueError, match="Malformed audit"):
        parse_audit_record('type=EXECVE msg=audit(1794996001.123:450): a0="broken')
