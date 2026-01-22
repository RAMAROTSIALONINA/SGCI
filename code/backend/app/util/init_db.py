"""
Outil simple pour creer les tables de la base de donnees.
Il utilise les modeles SQLAlchemy pour construire les tables.
"""
from app.core.database import Base, engine, SessionLocal

from app.db.models.user import User  # Import all models here

from app.db.models.twofa_code import TwoFACode  # Import all models here
from app.db.models.role import Role  # Import all models here
from app.db.models.permission import Permission  # Import all models here
from app.db.models.role_permission import RolePermission  # Import all models here

from app.service.roleService import RoleService


def create_tables():
    """
    Cree toutes les tables definies par les modeles.
    Utile au demarrage ou lors d'une installation.
    """
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        RoleService(session=session).seed_roles()
    finally:
        session.close()
