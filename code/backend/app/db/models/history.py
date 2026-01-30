"""
Modele SQLAlchemy pour l'historique des actions.
"""

from app.core.database import Base
from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


class History(Base):
    """
    Represente une entree d'historique.
    """

    __tablename__ = "Histories"

    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("Users.id", ondelete="SET NULL"), index=True)
    actor_role = Column(String(50))

    action = Column(String(80), nullable=False, index=True)
    entity_type = Column(String(50), index=True)
    entity_id = Column(Integer, index=True)
    module = Column(String(40), index=True)
    description = Column(String(255))
    meta = Column(JSON)

    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    actor = relationship("User")
