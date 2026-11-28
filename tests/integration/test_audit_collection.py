import gzip

from linuxtrace.collectors.audit import AuditCollector
from linuxtrace.parsers.audit_groups import group_audit_events

SYSCALL = 'type=SYSCALL msg=audit(1794996001.123:450): pid=1200 uid=1000 comm="cat"\n'

EXECVE = 'type=EXECVE msg=audit(1794996001.123:450): argc=2 a0="cat" a1="/etc/hosts"\n'

CWD = 'type=CWD msg=audit(1794996001.123:450): cwd="/home/analyst"\n'

PATH = 'type=PATH msg=audit(1794996001.123:450): item=0 name="/etc/hosts"\n'

LOGIN = 'type=USER_LOGIN msg=audit(1794996010.456:451): acct="analyst" res=success\n'


def prepare(tmp_path):
    root = tmp_path / "evidence"
    audit_dir = root / "var/log/audit"
    audit_dir.mkdir(parents=True)
    return root, audit_dir


def test_audit_collector_reads_records(tmp_path):
    root, audit_dir = prepare(tmp_path)

    (audit_dir / "audit.log").write_text(SYSCALL + EXECVE + CWD + PATH + LOGIN)

    collector = AuditCollector(root)
    records = list(collector.collect())

    assert collector.errors == []
    assert len(records) == 5
    assert all(record.source == "auditd" for record in records)
    assert [record.source_line for record in records] == [1, 2, 3, 4, 5]


def test_audit_records_grouped_by_event(tmp_path):
    root, audit_dir = prepare(tmp_path)

    (audit_dir / "audit.log").write_text(SYSCALL + EXECVE + CWD + PATH + LOGIN)

    raw_events = list(AuditCollector(root).collect())
    result = group_audit_events(raw_events)

    assert result.errors == []
    assert len(result.groups) == 2

    first = result.groups[0]
    assert first.serial == 450
    assert first.record_types == ["SYSCALL", "EXECVE", "CWD", "PATH"]

    second = result.groups[1]
    assert second.serial == 451
    assert second.record_types == ["USER_LOGIN"]


def test_command_arguments_preserved(tmp_path):
    root, audit_dir = prepare(tmp_path)
    (audit_dir / "audit.log").write_text(SYSCALL + EXECVE)

    records = list(AuditCollector(root).collect())
    result = group_audit_events(records)

    group = result.groups[0]
    fields = group.fields_for("EXECVE")

    assert fields[0]["a0"] == "cat"
    assert fields[0]["a1"] == "/etc/hosts"


def test_multiple_path_records_preserved(tmp_path):
    root, audit_dir = prepare(tmp_path)

    second_path = PATH.replace(
        'item=0 name="/etc/hosts"',
        'item=1 name="/tmp/output"',
    )

    (audit_dir / "audit.log").write_text(SYSCALL + PATH + second_path)

    records = list(AuditCollector(root).collect())
    result = group_audit_events(records)

    paths = result.groups[0].fields_for("PATH")

    assert len(paths) == 2
    assert paths[0]["name"] == "/etc/hosts"
    assert paths[1]["name"] == "/tmp/output"


def test_rotated_gzip_audit_file(tmp_path):
    root, audit_dir = prepare(tmp_path)

    with gzip.open(audit_dir / "audit.log.1.gz", "wb") as file:
        file.write(SYSCALL.encode("utf-8"))

    collector = AuditCollector(root)
    records = list(collector.collect())

    assert collector.errors == []
    assert len(records) == 1
    assert records[0].source_file.endswith(".gz")


def test_symlink_audit_file_rejected(tmp_path):
    root, audit_dir = prepare(tmp_path)

    outside = tmp_path / "outside.log"
    outside.write_text(SYSCALL)

    (audit_dir / "audit.log").symlink_to(outside)

    collector = AuditCollector(root)
    records = list(collector.collect())

    assert records == []
    assert collector.errors


def test_missing_audit_directory(tmp_path):
    collector = AuditCollector(tmp_path)

    assert list(collector.collect()) == []
    assert collector.errors == []


def test_invalid_audit_record_reported(tmp_path):
    root, audit_dir = prepare(tmp_path)

    (audit_dir / "audit.log").write_text(SYSCALL + "invalid audit record\n")

    records = list(AuditCollector(root).collect())
    result = group_audit_events(records)

    assert len(result.groups) == 1
    assert len(result.errors) == 1


def test_same_serial_different_timestamp_not_merged(tmp_path):
    root, audit_dir = prepare(tmp_path)

    different_timestamp = SYSCALL.replace(
        "1794996001.123",
        "1794996010.123",
    )

    (audit_dir / "audit.log").write_text(SYSCALL + different_timestamp)

    records = list(AuditCollector(root).collect())
    result = group_audit_events(records)

    assert result.errors == []
    assert len(result.groups) == 2
