import gzip
import sqlite3

from linuxtrace.collectors.audit_import import import_audit


def make_root(tmp_path):
    root = tmp_path / "evidence"
    audit_dir = root / "var/log/audit"
    audit_dir.mkdir(parents=True)
    return root, audit_dir


def test_streaming_import_many_events(tmp_path):
    root, audit_dir = make_root(tmp_path)

    count = 100

    with (audit_dir / "audit.log").open("w") as file:
        for serial in range(1, count + 1):
            file.write(
                f'type=SYSCALL msg=audit(1794996001.123:{serial}): pid={serial} comm="test"\n'
            )

    db_path = tmp_path / "events.db"

    first = import_audit(root, db_path)
    second = import_audit(root, db_path)

    assert first.errors == []
    assert first.records_read == count
    assert first.groups_read == count
    assert first.events_inserted == count
    assert first.evidence_inserted == count

    assert second.errors == []
    assert second.events_inserted == 0
    assert second.evidence_inserted == 0

    with sqlite3.connect(db_path) as conn:
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        evidence = conn.execute("SELECT COUNT(*) FROM audit_event_evidence").fetchone()[0]

    assert events == count
    assert evidence == count


def test_streaming_import_correlates_rotated_files(tmp_path):
    root, audit_dir = make_root(tmp_path)

    (audit_dir / "audit.log").write_text(
        'type=SYSCALL msg=audit(1794996001.123:450): pid=1200 comm="cat"\n'
    )

    with gzip.open(audit_dir / "audit.log.1.gz", "wb") as file:
        file.write(b'type=PATH msg=audit(1794996001.123:450): item=0 name="/etc/hosts"\n')

    db_path = tmp_path / "events.db"
    result = import_audit(root, db_path)

    assert result.errors == []
    assert result.records_read == 2
    assert result.groups_read == 1
    assert result.events_inserted == 1
    assert result.evidence_inserted == 2

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT record_type
            FROM audit_event_evidence
            ORDER BY record_type
            """
        ).fetchall()

    assert [row[0] for row in rows] == ["PATH", "SYSCALL"]
