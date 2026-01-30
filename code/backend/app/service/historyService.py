"""
Couche service pour l'historique des actions.
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.repository.historyRepo import HistoryRepository
from app.db.schema.history import HistoryOutput
from app.db.schema.user import UserOutput
from app.util.roles.role_utils import is_superadmin_role


class HistoryService:
    """
    Regroupe les actions liees a l'historique.
    """

    def __init__(self, session: Session):
        self.__repo = HistoryRepository(session=session)

    def log_action(
        self,
        action: str,
        actor_id: int | None,
        actor_role: str | None,
        entity_type: str | None = None,
        entity_id: int | None = None,
        module: str | None = None,
        description: str | None = None,
        meta: dict | None = None,
    ) -> HistoryOutput:
        """
        Enregistre une action dans l'historique.
        """
        item = self.__repo.create_history(
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            module=module,
            description=description,
            meta=meta,
        )
        return self._to_output(item)

    def list_history(
        self,
        current_user: UserOutput,
        actor_id: int | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[HistoryOutput]:
        """
        Liste l'historique selon les droits de l'utilisateur courant.
        """
        resolved_actor_id = self._resolve_actor_id(
            current_user=current_user,
            actor_id=actor_id,
        )

        limit = max(1, min(limit, 200))
        offset = max(0, offset)

        items = self.__repo.list_history(
            actor_id=resolved_actor_id,
            action=action,
            entity_type=entity_type,
            limit=limit,
            offset=offset,
        )
        return [self._to_output(item) for item in items]

    def _resolve_actor_id(
        self,
        *,
        current_user: UserOutput,
        actor_id: int | None,
    ) -> int | None:
        if is_superadmin_role(current_user.role):
            return actor_id
        if actor_id is not None and actor_id != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="User is not allowed to access this history.",
            )
        return current_user.id

    def _to_output(self, item) -> HistoryOutput:
        """
        Transforme un modele History en schema Pydantic.
        """
        return HistoryOutput(
            id=item.id,
            actor_id=item.actor_id,
            actor_role=item.actor_role,
            action=item.action,
            entity_type=item.entity_type,
            entity_id=item.entity_id,
            module=item.module,
            description=item.description,
            meta=item.meta,
            created_at=item.created_at,
        )
