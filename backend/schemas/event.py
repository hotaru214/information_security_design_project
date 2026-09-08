from datetime import datetime, timedelta
from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, field_validator


class EventCreate(BaseModel):
    timestamp: datetime
    host: str = Field(min_length=1)
    source: Literal[
        "windows_evtx", "sysmon", "linux_auth", "linux_audit",
        "network_pcap", "network_zeek",
    ]
    event_id: int | None = Field(
        validation_alias=AliasChoices("event_id", "source_event_id")
    )
    event_type: str = Field(min_length=1)
    user: str | None
    process: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None = Field(ge=1, le=65535)
    protocol: str | None
    logon_type: int | None
    session_id: str | None
    cmdline: str | None
    detail: dict
    description: str = Field(min_length=1)
    anomaly_flags: list[str]
    severity: int = Field(ge=0, le=3)
    raw_log: str = Field(min_length=1)

    @field_validator("timestamp")
    @classmethod
    def require_utc8(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(hours=8):
            raise ValueError("timestamp must include the +08:00 timezone")
        return value


class EventOut(EventCreate):
    id: int
