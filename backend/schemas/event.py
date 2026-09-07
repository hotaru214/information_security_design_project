from datetime import datetime

from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    timestamp: datetime
    host: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    dst_port: int = Field(ge=1, le=65535)
    protocol: str = Field(min_length=1)
    description: str


class EventOut(EventCreate):
    id: int
