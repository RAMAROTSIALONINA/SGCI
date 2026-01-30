"""
Couche service pour les notifications.
"""

from datetime import datetime, timezone

from app.db.repository.notificationRepo import NotificationRepository
from app.db.schema.notification import NotificationOutput
from fastapi import HTTPException
from sqlalchemy.orm import Session


class NotificationService:
    """
    Regroupe les actions liees aux notifications.
    """

    def __init__(self, session: Session):
        self.__repo = NotificationRepository(session=session)

    def list_for_user(self, user_id: int) -> list[NotificationOutput]:
        """
        Liste les notifications d'un utilisateur.
        """
        items = self.__repo.list_for_user(user_id=user_id)
        return [self._to_output(item) for item in items]

    def get_for_user(self, user_id: int, notification_id: int) -> NotificationOutput:
        """
        Recupere une notification par id pour l'utilisateur courant.
        """
        item = self._get_for_user_or_404(user_id, notification_id)
        return self._to_output(item)

    def mark_read(self, user_id: int, notification_id: int) -> NotificationOutput:
        """
        Marque la notification comme lue pour l'utilisateur courant.
        """
        item = self._get_for_user_or_404(user_id, notification_id)
        if not item.is_read:
            item.is_read = True
            item.read_at = datetime.now(timezone.utc)
            item = self.__repo.mark_read(notification=item)

        return self._to_output(item)

    def _get_for_user_or_404(self, user_id: int, notification_id: int):
        item = self.__repo.get_by_id_or_404(notification_id)
        if item.user_id != user_id:
            raise HTTPException(status_code=404, detail="Notification not found.")
        return item

    def _to_output(self, item) -> NotificationOutput:
        return NotificationOutput(
            id=item.id,
            user_id=item.user_id,
            title=item.title,
            body=item.body,
            category=item.category,
            is_read=item.is_read,
            read_at=item.read_at,
            created_at=item.created_at,
        )
