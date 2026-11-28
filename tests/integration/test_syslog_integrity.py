from linuxtrace.collectors.syslog_import import import_syslog

VALID_LINE = "Nov 18 10:00:01 lab-server systemd[1]: Started Daily Cleanup Service.\n"


def make_evidence(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)
    return root, log_dir


def collect(root, db_path):
    return import_syslog(
        root=root,
        db_path=db_path,
        year=2026,
        source_timezone="Europe/Istanbul",
    )


def test_corrupted_gzip_prevents_partial_import(tmp_path):
    root, log_dir = make_evidence(tmp_path)
    db_path = tmp_path / "events.db"

    (log_dir / "syslog").write_text(VALID_LINE)
    (log_dir / "syslog.1.gz").write_bytes(b"This is not a valid gzip file")

    result = collect(root, db_path)

    assert result.errors
    assert result.inserted == 0
    assert not db_path.exists()


def test_normalization_failure_prevents_import(tmp_path, monkeypatch):
    from linuxtrace.collectors import syslog_import

    root, log_dir = make_evidence(tmp_path)
    db_path = tmp_path / "events.db"

    (log_dir / "syslog").write_text(VALID_LINE * 2)

    original = syslog_import.normalize_event
    calls = 0

    def failing_normalizer(*args, **kwargs):
        nonlocal calls
        calls += 1

        if calls == 2:
            raise ValueError("Simulated normalization failure")

        return original(*args, **kwargs)

    monkeypatch.setattr(
        syslog_import,
        "normalize_event",
        failing_normalizer,
    )

    result = collect(root, db_path)

    assert calls == 2
    assert result.errors
    assert result.inserted == 0
    assert not db_path.exists()


def test_symlink_outside_evidence_is_rejected(tmp_path):
    root, log_dir = make_evidence(tmp_path)
    db_path = tmp_path / "events.db"

    outside = tmp_path / "outside.log"
    outside.write_text(VALID_LINE)

    (log_dir / "syslog").symlink_to(outside)

    result = collect(root, db_path)

    assert result.inserted == 0
    assert result.errors
    assert not db_path.exists()
