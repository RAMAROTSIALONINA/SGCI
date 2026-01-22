"""
Docstring for main
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends

from app.util.init_db import create_tables

from app.routes.auth import auth_router
from app.routes.roles import roles_router
from app.routes.users import users_router

from app.util.protectRoute import get_current_user

from app.db.schema.user import UserOutput


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Creating database tables...")
    create_tables()
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(auth_router, tags=["auth"], prefix="/auth")
app.include_router(roles_router, tags=["roles"], prefix="/roles")
app.include_router(users_router, tags=["users"], prefix="/users")


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
