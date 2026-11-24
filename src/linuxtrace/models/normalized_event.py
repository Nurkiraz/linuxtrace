from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import Field, field_validator

from linuxtrace.models.parsed_event import ParsedEvent


class TimestampConfidence(StrEnum):
    """Confidence level of an event timestamp."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class NormalizedEvent(ParsedEvent):
    """Normalized forensic event ready for storage."""

    event_id: str = Field(pattern=r"^[a-f0-9]{64}$")

    timestamp: datetime | None = None
    timezone: str | None = None

    timestamp_confidence: TimestampConfidence = TimestampConfidence.UNKNOWN

    timestamp_method: str | None = None

    normalization_warnings: list[str] = Field(default_factory=list)

    destination_ip: str | None = None

    mitre_technique: list[str] = Field(default_factory=list)

    related_event_ids: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime | None) -> datetime | None:
        """Require normalized timestamps to use UTC."""

        if value is None:
            return None

        if value.tzinfo is None:
            raise ValueError("Timestamp must be timezone-aware")

        if value.utcoffset() != timedelta(0):
            raise ValueError("Timestamp must use UTC")

        return value
