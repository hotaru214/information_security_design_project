from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.database import init_db
from backend.routers.events import router
from backend.routers.hosts import router as hosts_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Attack Trace Analysis System",
    lifespan=lifespan,
)
app.include_router(router)
app.include_router(hosts_router)


@app.get("/health")
def health():
    return {"status": "ok"}
