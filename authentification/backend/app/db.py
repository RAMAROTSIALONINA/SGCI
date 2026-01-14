"""Base de données et session"""

import os

from dotenv import load_dotenv

from sqlalchemy import create_engine

from sqlalchemy.orm import sessionmaker, DeclarativeBase


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL n'est pas defini dans le fichier .env")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """Base declarative pour les modeles SQLAlchemy"""


def get_db():
    """Dependency pour obtenir une session de base de donnees"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
