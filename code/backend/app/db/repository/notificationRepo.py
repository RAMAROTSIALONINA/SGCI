"""
Acces aux donnees pour les notifications.
Ici on lit et on ecrit dans la table Notifications.
"""

from app.db.models.notification import Notification
from fastapi import HTTPException

from .base import BaseRepository


class NotificationRepository(BaseRepository):
    """
    Fournit des operations simples pour la table Notifications.
    """

    def add_notification(
        self,
        user_id: int,
        title: str,
        body: str | None = None,
        category: str = "general",
    ) -> Notification:
        """
        Ajoute une notification a la session sans commit immediat.
        """
        notification = Notification(
            user_id=user_id,
            title=title,
            body=body,
            category=category,
        )
        self.session.add(notification)
        return notification

    def create_notification(
        self,
        user_id: int,
        title: str,
        body: str | None = None,
        category: str = "general",
    ) -> Notification:
        """
        Cree une notification en base de donnees.
        """
        notification = self.add_notification(
            user_id=user_id,
            title=title,
            body=body,
            category=category,
        )
        return self._save(notification)

    def list_for_user(self, user_id: int) -> list[Notification]:
        """
        Retourne les notifications d'un utilisateur (les plus recentes en premier).
        """
        return (
            self.session.query(Notification)
            .filter(Notification.user_id == user_id)
            .order_by(Notification.created_at.desc())
            .all()
        )

    def get_by_id(self, notification_id: int) -> Notification | None:
        """
        Recupere une notification par identifiant.
        """
        return (
            self.session.query(Notification)
            .filter(Notification.id == notification_id)
            .first()
        )

    def get_by_id_or_404(
        self,
        notification_id: int,
        *,
        detail: str = "Notification not found.",
    ) -> Notification:
        """
        Recupere une notification ou leve une HTTPException 404.
        """
        notification = self.get_by_id(notification_id)
        if not notification:
            raise HTTPException(status_code=404, detail=detail)
        return notification

    def exists_by_id(self, notification_id: int) -> bool:
        """
        Indique si une notification existe.
        """
        return (
            self.session.query(Notification.id)
            .filter(Notification.id == notification_id)
            .first()
            is not None
        )

    def mark_read(self, notification: Notification) -> Notification:
        """
        Marque une notification comme lue.
        """
        return self._save(notification)
