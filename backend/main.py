from contextlib import asynccontextmanager

from fastapi import FastAPI

import db


@asynccontextmanager
async def lifespan(app):
    db.init()
    yield


app = FastAPI(title="VibeGuard", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True}
