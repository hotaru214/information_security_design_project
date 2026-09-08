import sqlite3

from fastapi import APIRouter, HTTPException, status

from backend.database import get_host_map, get_hosts, insert_host, insert_hosts
from backend.schemas.host import HostCreate, HostOut


router = APIRouter(prefix="/api/hosts")


@router.post("", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def create_host(host: HostCreate):
    try:
        return insert_host(host)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Hostname or IP already exists") from exc


@router.post("/batch", status_code=status.HTTP_201_CREATED)
def create_hosts(hosts: list[HostCreate]):
    try:
        return {"inserted": insert_hosts(hosts)}
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Hostname or IP already exists") from exc


@router.get("", response_model=list[HostOut])
def list_hosts():
    return get_hosts()


@router.get("/map", response_model=dict[str, str])
def host_map():
    return get_host_map()
