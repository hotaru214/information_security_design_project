from fastapi import APIRouter, status

from backend.database import get_events, insert_event, insert_events
from backend.schemas.event import EventCreate, EventOut


router = APIRouter(prefix="/api/events")


@router.post("", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def create_event(event: EventCreate):
    return insert_event(event)


@router.post("/batch", status_code=status.HTTP_201_CREATED)
def create_events(events: list[EventCreate]):
    return {"inserted": insert_events(events)}


@router.get("", response_model=list[EventOut])
def list_events():
    return get_events()
