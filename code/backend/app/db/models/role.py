"""
Modele SQLAlchemy pour la table des roles.
Il decrit les colonnes qui seront creees en base.
"""

from app.core.database import Base
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship


class Role(Base):
    """
    Represente un role en base de donnees.
    Chaque attribut devient une colonne dans la table "Roles".
    """

    __tablename__ = "Roles"
    id = Column(Integer, primary_key=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    level = Column(Integer, nullable=False)
    is_system = Column(Boolean, default=True, nullable=False)
    is_assistant = Column(Boolean, default=False, nullable=False)
    created_by_id = Column(Integer, ForeignKey("Users.id"))
    permissions = relationship(
        "Permission",
        secondary="RolePermissions",
        back_populates="roles",
    )
