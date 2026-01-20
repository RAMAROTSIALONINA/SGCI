"""
Modele SQLAlchemy pour la table des utilisateurs.
Il decrit les colonnes qui seront creees en base.
"""
from sqlalchemy import Column, Integer, String, Boolean

from app.core.database import Base


class User(Base):
    """
    Represente un utilisateur en base de donnees.
    Chaque attribut devient une colonne dans la table "Users".
    """
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True)
    first_name = Column(String(50))
    last_name = Column(String(100))
    email = Column(String(100), unique=True, index=True)
    password = Column(String(250))
    role = Column(String(50))

    is_active = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)



