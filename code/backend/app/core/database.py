"""
Configuration de la base de donnees SQLAlchemy.
On y cree le moteur, la session, et la base declarative.
"""

from decouple import config
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

SQLALCHEMY_DATABASE_URL = config(
    "DATABASE_URL",
    default="postgresql+psycopg://user:password@localhost:5433/postgres",
)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Dependance FastAPI qui fournit une session de base de donnees.
    Elle ouvre la session, la rend au code appelant, puis la ferme.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
