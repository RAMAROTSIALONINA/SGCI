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

    def _save(self, instance):
        """
        Ajoute si necessaire, commit, puis rafraichit l'instance.
        """
        self.session.add(instance)
        self.session.commit()
        self.session.refresh(instance)
        return instance

    def _delete(self, instance) -> None:
        """
        Supprime puis commit.
        """
        self.session.delete(instance)
        self.session.commit()
