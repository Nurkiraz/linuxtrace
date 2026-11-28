import pytest

from linuxtrace.parsers.system_events import classify_system_event


@pytest.mark.parametrize(
    ("process", "message", "category", "event_type", "severity"),
    [
        (
            "systemd",
            "Started Daily Cleanup Service.",
            "service",
            "service_started",
            "info",
        ),
        (
            "systemd",
            "backup.service: Failed with result 'exit-code'.",
            "service",
            "service_failed",
            "medium",
        ),
        (
            "CRON",
            "(root) CMD (/usr/local/bin/backup.sh)",
            "scheduled_task",
            "cron_execution",
            "info",
        ),
        (
            "kernel",
            "[12345.678901] eth0: link down",
            "kernel",
            "kernel_message",
            "info",
        ),
        (
            "rsyslogd",
            "rsyslogd was HUPed",
            "system",
            "system_message",
            "info",
        ),
    ],
)
def test_system_event_classification(
    process,
    message,
    category,
    event_type,
    severity,
):
    result = classify_system_event(process, message)

    assert result.category == category
    assert result.event_type == event_type
    assert result.severity == severity


def test_unknown_process():
    result = classify_system_event(
        None,
        "Unknown system message",
    )

    assert result.event_type == "system_message"


def test_service_failure_case_insensitive():
    result = classify_system_event(
        "SYSTEMD",
        "backup.service: FAILED WITH RESULT 'exit-code'.",
    )

    assert result.event_type == "service_failed"


def test_cron_without_command_is_not_execution():
    result = classify_system_event(
        "CRON",
        "CRON service initialized",
    )

    assert result.event_type == "system_message"
