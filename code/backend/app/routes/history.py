"""
Routes HTTP pour l'historique.
"""

from app.core.database import get_db
from app.db.schema.history import HistoryOutput
from app.db.schema.user import UserOutput
from app.service.historyService import HistoryService
from app.util.protectRoute import get_current_user
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

history_router = APIRouter()


def get_history_service(session: Session = Depends(get_db)) -> HistoryService:
    return HistoryService(session=session)


@history_router.get("/", status_code=200, response_model=list[HistoryOutput])
def list_history(
    actor_id: int | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
    service: HistoryService = Depends(get_history_service),
    current_user: UserOutput = Depends(get_current_user),
):
    """
    Liste l'historique (superadmin: tout, autres: uniquement leurs actions).
    """
    return service.list_history(
        current_user=current_user,
        actor_id=actor_id,
        action=action,
        entity_type=entity_type,
        limit=limit,
        offset=offset,
    )
