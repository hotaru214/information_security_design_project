from fastapi import APIRouter, HTTPException, Path, Query, status

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
def import_events(events: list[EventCreate], case_id: str | None = Query(default=None, min_length=1)):
    # Explicit import scope is independent of detail.batch_id.
    if case_id is not None:
        if any(event.case_id not in (None, case_id) for event in events):
            raise HTTPException(status_code=422, detail="Event case_id conflicts with import case_id")
        events = [event.model_copy(update={"case_id": case_id}) for event in events]
    return {"imported": insert_events(events), "failed": 0}


@router.get("", response_model=list[EventOut])
def list_events(case_id: str | None = Query(default=None, min_length=1)):
    return get_events(case_id=case_id)


@router.get("/{event_id}", response_model=EventOut)
def read_event(event_db_id: int = Path(alias="event_id")):
    event = get_event_by_id(event_db_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
