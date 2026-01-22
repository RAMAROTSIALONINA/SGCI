"""
Modele SQLAlchemy pour la table des permissions.
Il decrit les colonnes qui seront creees en base.
"""
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import relationship

from app.core.database import Base


class Permission(Base):
    """
    Represente une permission en base de donnees.
    Chaque attribut devient une colonne dans la table "Permissions".
    """
    __tablename__ = "Permissions"
    id = Column(Integer, primary_key=True)
    code = Column(String(80), unique=True, index=True, nullable=False)
    name = Column(String(120), nullable=False)
    description = Column(String(255))
    module = Column(String(50), index=True)
    is_system = Column(Boolean, default=True, nullable=False)

    roles = relationship(
        "Role",
        secondary="RolePermissions",
        back_populates="permissions",
    )
