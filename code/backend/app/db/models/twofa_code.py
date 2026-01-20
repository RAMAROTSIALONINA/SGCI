"""
Database pour la table des codes 2FA.
Il decrit les colonnes qui seront creees en base.
"""

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from app.core.database import Base


class TwoFACode(Base):
    """
    Represente un code 2FA en base de donnees.
    Chaque attribut devient une colonne dans la table "TwoFACodes".
    
    Attempts veut dire le nombre de tentatives de saisie du code.
    """
    __tablename__ = "TwoFACodes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("Users.id", ondelete="CASCADE"), index=True, nullable=False)

    code_hash = Column(String(100), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True))

    attempts = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User")