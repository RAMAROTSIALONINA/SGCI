"""
Schemas Pydantic pour les notifications.
"""

from datetime import datetime

from pydantic import BaseModel


class NotificationOutput(BaseModel):
    """
    Donnees renvoyees au client pour une notification.
    """

    id: int
    user_id: int
    title: str
    body: str | None = None
    category: str
    is_read: bool
    read_at: datetime | None = None
    created_at: datetime
