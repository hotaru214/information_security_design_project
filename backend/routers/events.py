from fastapi import APIRouter, HTTPException, Path, status

from backend.database import get_event_by_id, get_events, insert_event, insert_events
from backend.schemas.event import EventCreate, EventOut


router = APIRouter(prefix="/api/events")


@router.post("", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def create_event(event: EventCreate):
    return insert_event(event)


@router.post("/batch", status_code=status.HTTP_201_CREATED)
def create_events(events: list[EventCreate]):
    return {"inserted": insert_events(events)}


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_events(events: list[EventCreate]):
    return {"imported": insert_events(events), "failed": 0}


@router.get("", response_model=list[EventOut])
def list_events():
    return get_events()


@router.get("/{event_id}", response_model=EventOut)
def read_event(event_db_id: int = Path(alias="event_id")):
    event = get_event_by_id(event_db_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
