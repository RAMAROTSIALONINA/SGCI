"""
Routes HTTP pour les notifications.
"""

from app.core.database import get_db
from app.db.schema.notification import NotificationOutput
from app.db.schema.user import UserOutput
from app.service.notificationService import NotificationService
from app.util.protectRoute import get_current_user
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

notifications_router = APIRouter()


def get_notification_service(
    session: Session = Depends(get_db),
) -> NotificationService:
    return NotificationService(session=session)


@notifications_router.get("/", status_code=200, response_model=list[NotificationOutput])
def list_notifications(
    service: NotificationService = Depends(get_notification_service),
    current_user: UserOutput = Depends(get_current_user),
):
    """
    Liste les notifications de l'utilisateur courant.
    """
    return service.list_for_user(current_user.id)


@notifications_router.get(
    "/{notification_id}", status_code=200, response_model=NotificationOutput
)
def get_notification(
    notification_id: int,
    service: NotificationService = Depends(get_notification_service),
    current_user: UserOutput = Depends(get_current_user),
):
    """
    Retourne une notification de l'utilisateur courant.
    """
    return service.get_for_user(
        user_id=current_user.id,
        notification_id=notification_id,
    )


@notifications_router.patch(
    "/{notification_id}/read",
    status_code=200,
    response_model=NotificationOutput,
)
def mark_notification_read(
    notification_id: int,
    service: NotificationService = Depends(get_notification_service),
    current_user: UserOutput = Depends(get_current_user),
):
    """
    Marque une notification comme lue pour l'utilisateur courant.
    """
    return service.mark_read(
        user_id=current_user.id,
        notification_id=notification_id,
    )
