"""
Schemas Pydantic pour l'historique.
"""

from datetime import datetime

from pydantic import BaseModel


class HistoryOutput(BaseModel):
    """
    Donnees renvoyees pour une entree d'historique.
    """

    id: int
    actor_id: int | None = None
    actor_role: str | None = None
    action: str
    entity_type: str | None = None
    entity_id: int | None = None
    module: str | None = None
    description: str | None = None
    meta: dict | None = None
    created_at: datetime

    class Config:
        from_attributes = True
