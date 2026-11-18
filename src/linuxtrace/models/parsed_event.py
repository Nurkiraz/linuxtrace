from pydantic import BaseModel

from linuxtrace.models.raw_event import RawEvent


class ParsedEvent(BaseModel):
    """Represent a parsed security event."""

    raw_event: RawEvent

    timestamp_original: str | None = None
    hostname: str | None = None

    event_category: str
    event_type: str

    severity: str = "info"

    username: str | None = None
    source_ip: str | None = None
    source_port: int | None = None

    process_name: str | None = None
    process_id: int | None = None

    authentication_method: str | None = None
    outcome: str | None = None

    command: str | None = None
    target_user: str | None = None

    pam_module: str | None = None
    pam_service: str | None = None
    pam_type: str | None = None

    user_id: int | None = None
    actor_user: str | None = None
    actor_uid: int | None = None
    terminal: str | None = None
    working_directory: str | None = None
    boot_id: str | None = None
    session_id: str | None = None
    journal_cursor: str | None = None
    systemd_unit: str | None = None
    journal_priority: int | None = None
    timestamp_unix_us: int | None = None
    process_uid: int | None = None

    description: str
