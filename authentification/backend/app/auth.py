"""
Docstring for SGCI.authentification.backend.app.auth
"""

from datetime import datetime, timezone
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .db import get_db
from . import models, schema
from .security import hash_password, verify_password
from .tokens import create_access_token, create_refresh_token

router = APIRouter(prefix="/auth", tags=["auth"])


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@router.post("/register", status_code=201)
def register(
    payload: schema.UserCreate, db: Session = Depends(get_db)
) -> dict[str, object]:
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    role = db.query(models.Role).filter(models.Role.name == payload.role).first()
    if not role:
        role = models.Role(name=payload.role)
        db.add(role)
        db.flush()

    user = models.User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role_id=role.id,
    )
    db.add(user)
    db.commit()
    return {"id": user.id, "email": user.email, "role": role.name}


def is_user_active(user: models.User) -> bool:
    return bool(getattr(user, "is_active", True))


@router.post("/login", response_model=schema.TokenPair)
def login(payload: schema.LoginData, db: Session = Depends(get_db)) -> schema.TokenPair:
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if not is_user_active(user):
        raise HTTPException(status_code=403, detail="User inactive")

    access = create_access_token(sub=str(user.id))
    refresh, refresh_exp = create_refresh_token(sub=str(user.id))

    # on stocke un hash du refresh token (pas le token en clair)
    db.add(
        models.RefreshToken(
            user_id=user.id,
            token_hash=sha256(refresh),
            revoked=False,
            expires_at=refresh_exp,
        )
    )
    db.commit()

    return schema.TokenPair(
        access_token=access, refresh_token=refresh, token_type="bearer"
    )


@router.post("/refresh", response_model=schema.TokenPair)
def refresh(refresh_token: str, db: Session = Depends(get_db)) -> schema.TokenPair:
    token_h = sha256(refresh_token)
    row = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.token_hash == token_h)
        .first()
    )
    if not row:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if row.revoked:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = db.query(models.User).filter(models.User.id == row.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not valid")
    if not is_user_active(user):
        raise HTTPException(status_code=401, detail="User not valid")

    access = create_access_token(sub=str(user.id))
    new_refresh, new_exp = create_refresh_token(sub=str(user.id))

    # rotation: révoque l'ancien, crée un nouveau
    row.revoked = True
    db.add(
        models.RefreshToken(
            user_id=user.id,
            token_hash=sha256(new_refresh),
            revoked=False,
            expires_at=new_exp,
        )
    )
    db.commit()

    return schema.TokenPair(
        access_token=access, refresh_token=new_refresh, token_type="bearer"
    )


@router.post("/logout")
def logout(refresh_token: str, db: Session = Depends(get_db)) -> dict[str, bool]:
    token_h = sha256(refresh_token)
    row = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.token_hash == token_h)
        .first()
    )
    if row:
        row.revoked = True
        db.commit()
    return {"ok": True}
