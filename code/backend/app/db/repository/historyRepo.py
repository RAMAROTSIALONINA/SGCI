"""
Acces aux donnees pour l'historique.
"""

from app.db.models.history import History
from fastapi import HTTPException

from .base import BaseRepository


class HistoryRepository(BaseRepository):
    """
    Fournit des operations simples pour la table Histories.
    """

    def add_history(
        self,
        actor_id: int | None,
        actor_role: str | None,
        action: str,
        entity_type: str | None = None,
        entity_id: int | None = None,
        module: str | None = None,
        description: str | None = None,
        meta: dict | None = None,
    ) -> History:
        """
        Ajoute une entree d'historique sans commit immediat.
        """
        history = History(
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            module=module,
            description=description,
            meta=meta,
        )
        self.session.add(history)
        return history

    def create_history(
        self,
        actor_id: int | None,
        actor_role: str | None,
        action: str,
        entity_type: str | None = None,
        entity_id: int | None = None,
        module: str | None = None,
        description: str | None = None,
        meta: dict | None = None,
    ) -> History:
        """
        Cree une entree d'historique.
        """
        history = self.add_history(
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            module=module,
            description=description,
            meta=meta,
        )
        return self._save(history)

    def get_by_id(self, history_id: int) -> History | None:
        """
        Recupere une entree d'historique par identifiant.
        """
        return self.session.query(History).filter(History.id == history_id).first()

    def get_by_id_or_404(
        self,
        history_id: int,
        *,
        detail: str = "History entry not found.",
    ) -> History:
        """
        Recupere une entree d'historique ou leve une HTTPException 404.
        """
        item = self.get_by_id(history_id)
        if not item:
            raise HTTPException(status_code=404, detail=detail)
        return item

    def exists_by_id(self, history_id: int) -> bool:
        """
        Indique si une entree d'historique existe.
        """
        return (
            self.session.query(History.id).filter(History.id == history_id).first()
            is not None
        )

    def list_history(
        self,
        actor_id: int | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[History]:
        """
        Liste les entrees d'historique (filtrables).
        """
        query = self.session.query(History)
        if actor_id is not None:
            query = query.filter(History.actor_id == actor_id)
        if action:
            query = query.filter(History.action == action)
        if entity_type:
            query = query.filter(History.entity_type == entity_type)
        return (
            query.order_by(History.created_at.desc()).offset(offset).limit(limit).all()
        )
