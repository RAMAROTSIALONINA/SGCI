"""
Modele SQLAlchemy pour les notifications utilisateur.
"""

from app.core.database import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


class Notification(Base):
    """
    Represente une notification associee a un utilisateur.
    """

    __tablename__ = "Notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer, ForeignKey("Users.id", ondelete="CASCADE"), index=True, nullable=False
    )

    title = Column(String(120), nullable=False)
    body = Column(String(500))
    category = Column(String(40), default="general", nullable=False)

    is_read = Column(Boolean, default=False, nullable=False)
    read_at = Column(DateTime(timezone=True))
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user = relationship("User")
