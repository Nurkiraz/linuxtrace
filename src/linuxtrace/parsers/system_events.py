import re
from dataclasses import dataclass

CRON_PATTERN = re.compile(r"\([^)]+\)\s+CMD\s+\(.+\)")

FAILED_SERVICE_PATTERN = re.compile(r"\bFailed with result\b", re.IGNORECASE)

STARTED_SERVICE_PATTERN = re.compile(r"^Started\b", re.IGNORECASE)


@dataclass(frozen=True)
class SystemEventClassification:
    """Classification of an already parsed system log message."""

    category: str
    event_type: str
    severity: str


def classify_system_event(
    process_name: str | None,
    message: str,
) -> SystemEventClassification:
    """Classify common Linux service and system log messages."""

    process = (process_name or "").lower()
    message = message.strip()

    if process == "systemd":
        if FAILED_SERVICE_PATTERN.search(message):
            return SystemEventClassification(
                category="service",
                event_type="service_failed",
                severity="medium",
            )

        if STARTED_SERVICE_PATTERN.search(message):
            return SystemEventClassification(
                category="service",
                event_type="service_started",
                severity="info",
            )

    if process in ("cron", "crond") and CRON_PATTERN.search(message):
        return SystemEventClassification(
            category="scheduled_task",
            event_type="cron_execution",
            severity="info",
        )

    if process == "kernel":
        return SystemEventClassification(
            category="kernel",
            event_type="kernel_message",
            severity="info",
        )

    return SystemEventClassification(
        category="system",
        event_type="system_message",
        severity="info",
    )
