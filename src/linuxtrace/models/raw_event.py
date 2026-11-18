from typing import Any

from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """Represent an unparsed log record."""

    source: str
    source_file: str
    source_line: int = Field(ge=1)
    raw_log: str
    evidence_hash: str

    metadata: dict[str, Any] = Field(default_factory=dict)
