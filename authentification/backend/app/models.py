"""La ou tous les modeles de la base de donnees sont definis"""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, Boolean, DateTime, text

from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Role(Base):
    """Creation du modele role"""

    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(
        String(50), unique=True, index=True, nullable=False
    )


class User(Base):
    """Creation du modele utilisateur"""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id"), nullable=False)
    role: Mapped[Role] = relationship("Role")

    created_at: Mapped["DateTime"] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class RefreshToken(Base):
    """Creation du modele de token de rafraichissement"""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped["DateTime"] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
