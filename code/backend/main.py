"""
Docstring for main
"""

import os
from contextlib import asynccontextmanager

from app.db.schema.user import UserOutput
from app.routes.auth import auth_router
from app.routes.history import history_router
from app.routes.notifications import notifications_router
from app.routes.roles import roles_router
from app.routes.users import users_router
from app.util.init_db import create_tables
from app.util.protectRoute import get_current_user
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Creating database tables...")
    create_tables()
    yield


app = FastAPI(lifespan=lifespan)

raw_origins = os.getenv("CORS_ORIGINS", "")
default_origins = {"http://localhost:3000", "http://127.0.0.1:3000"}
cors_origins = {
    origin.strip().rstrip("/") for origin in raw_origins.split(",") if origin.strip()
}
if not cors_origins:
    cors_origins = set(default_origins)
else:
    cors_origins.update(default_origins)

cors_origins = sorted(cors_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, tags=["auth"], prefix="/auth")
app.include_router(history_router, tags=["history"], prefix="/history")
app.include_router(roles_router, tags=["roles"], prefix="/roles")
app.include_router(users_router, tags=["users"], prefix="/users")
app.include_router(
    notifications_router, tags=["notifications"], prefix="/notifications"
)


@app.get("/health")
def health_check():
    """
    Health check endpoint
    """
    return {"status": "Running"}


@app.get("/protected")
def read_protected(user: UserOutput = Depends(get_current_user)):
    """
    Protected route example
    """
    return {"data": user}
