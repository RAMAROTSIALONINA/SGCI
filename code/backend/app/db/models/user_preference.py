"""
Modele SQLAlchemy pour les preferences utilisateur.
Stocke l'apparence (theme/palette) pour chaque utilisateur.
"""

from app.core.database import Base
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


class UserPreference(Base):
    """
    Represente les preferences d'apparence d'un utilisateur.
    """

    __tablename__ = "UserPreferences"
    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("Users.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )

    theme_mode = Column(String(20), default="light", nullable=False)
    palette = Column(String(40), default="oasis", nullable=False)

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    user = relationship("User")
