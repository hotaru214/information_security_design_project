from pydantic import BaseModel, Field


class HostCreate(BaseModel):
    hostname: str = Field(min_length=1)
    ip: str = Field(min_length=1)
    role: str | None = None


class HostOut(HostCreate):
    id: int
