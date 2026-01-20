"""
Base des repositories.
Contient la session SQLAlchemy partagee par les autres classes.
"""

from sqlalchemy.orm import Session


class BaseRepository:
    """
    Stocke la session de base de donnees pour les classes enfant.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
