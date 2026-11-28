"""Models for security detection findings."""

from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class FindingSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityFinding(BaseModel):
    """A detection result linked to forensic evidence."""

    finding_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)

    severity: FindingSeverity
    start_time: datetime
    end_time: datetime

    source_ip: str | None = None
    username: str | None = None

    related_event_ids: list[str] = Field(min_length=1)
    mitre_techniques: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_time_window(self):
        for value in (self.start_time, self.end_time):
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError("Finding timestamps must use UTC")

        if self.end_time < self.start_time:
            raise ValueError("end_time cannot precede start_time")

        return self
