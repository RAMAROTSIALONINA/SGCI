"""
Modele SQLAlchemy pour l'association role-permission.
Il decrit les colonnes qui seront creees en base.
"""
from sqlalchemy import Column, Integer, ForeignKey, UniqueConstraint

from app.core.database import Base


class RolePermission(Base):
    """
    Associe un role a une permission (many-to-many).
    """
    __tablename__ = "RolePermissions"
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("Roles.id", ondelete="CASCADE"), index=True, nullable=False)
    permission_id = Column(Integer, ForeignKey("Permissions.id", ondelete="CASCADE"), index=True, nullable=False)

    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )
