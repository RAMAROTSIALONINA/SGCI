from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from .db import get_db
from .settings import settings
from . import models

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def _is_user_active(user: models.User) -> bool:
    return bool(getattr(user, "is_active", True))


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> models.User:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
    )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not _is_user_active(user):
        raise HTTPException(status_code=401, detail="User not found/inactive")
    return user
