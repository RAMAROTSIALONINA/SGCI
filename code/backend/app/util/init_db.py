"""
Outil simple pour creer les tables de la base de donnees.
Il utilise les modeles SQLAlchemy pour construire les tables.
"""
from app.core.database import Base, engine

from app.db.models.user import User  # Import all models here

from app.db.models.twofa_code import TwoFACode  # Import all models here


def create_tables():
    """
    Cree toutes les tables definies par les modeles.
    Utile au demarrage ou lors d'une installation.
    """
    Base.metadata.create_all(bind=engine)
