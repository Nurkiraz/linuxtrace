from pathlib import Path

from linuxtrace.collectors.audit_spool import (
    iter_spooled_groups,
    spool_audit_records,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/audit"

LINE = 'type=SYSCALL msg=audit(1794996001.123:{serial}): pid={serial} comm="test"\n'


def test_spool_fixture(tmp_path):
    spool = tmp_path / "spool.db"

    result = spool_audit_records(FIXTURE, spool)
    groups = list(iter_spooled_groups(spool))

    assert result.errors == []
    assert result.records_read == 5
    assert result.groups_read == 2
    assert len(groups) == 2


def test_spool_preserves_related_records(tmp_path):
    spool = tmp_path / "spool.db"

    spool_audit_records(FIXTURE, spool)
    groups = list(iter_spooled_groups(spool))

    assert groups[0].serial == 450
    assert groups[0].record_types == ["SYSCALL", "EXECVE", "CWD", "PATH"]
    assert groups[1].serial == 451


def test_spool_preserves_evidence_metadata(tmp_path):
    spool = tmp_path / "spool.db"

    spool_audit_records(FIXTURE, spool)
    groups = list(iter_spooled_groups(spool))

    evidence = groups[0].records

    assert len(evidence) == 4
    assert [item.raw.source_line for item in evidence] == [1, 2, 3, 4]
    assert all(item.raw.evidence_hash for item in evidence)


def test_spool_reports_invalid_records(tmp_path):
    root = tmp_path / "evidence"
    audit_dir = root / "var/log/audit"
    audit_dir.mkdir(parents=True)

    (audit_dir / "audit.log").write_text(LINE.format(serial=100) + "invalid record\n")

    spool = tmp_path / "spool.db"
    result = spool_audit_records(root, spool)

    assert result.records_read == 2
    assert result.groups_read == 1
    assert len(result.errors) == 1


def test_spool_many_separate_events(tmp_path):
    root = tmp_path / "evidence"
    audit_dir = root / "var/log/audit"
    audit_dir.mkdir(parents=True)

    count = 1000

    (audit_dir / "audit.log").write_text(
        "".join(LINE.format(serial=i) for i in range(1, count + 1))
    )

    spool = tmp_path / "spool.db"
    result = spool_audit_records(root, spool)

    assert result.errors == []
    assert result.records_read == count
    assert result.groups_read == count

    groups_seen = 0

    for group in iter_spooled_groups(spool):
        assert len(group.records) == 1
        groups_seen += 1

    assert groups_seen == count


def test_spool_groups_records_across_files(tmp_path):
    root = tmp_path / "evidence"
    audit_dir = root / "var/log/audit"
    audit_dir.mkdir(parents=True)

    (audit_dir / "audit.log").write_text(LINE.format(serial=200))
    (audit_dir / "audit.log.1").write_text(
        'type=PATH msg=audit(1794996001.123:200): item=0 name="/etc/hosts"\n'
    )

    spool = tmp_path / "spool.db"
    result = spool_audit_records(root, spool)
    groups = list(iter_spooled_groups(spool))

    assert result.errors == []
    assert result.records_read == 2
    assert result.groups_read == 1
    assert len(groups) == 1
    assert set(groups[0].record_types) == {"SYSCALL", "PATH"}


def test_spool_rejects_symlink(tmp_path):
    root = tmp_path / "evidence"
    audit_dir = root / "var/log/audit"
    audit_dir.mkdir(parents=True)

    outside = tmp_path / "outside.log"
    outside.write_text(LINE.format(serial=300))

    (audit_dir / "audit.log").symlink_to(outside)

    spool = tmp_path / "spool.db"
    result = spool_audit_records(root, spool)

    assert result.errors
    assert result.groups_read == 0
