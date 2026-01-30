"""
Routes HTTP pour la gestion des utilisateurs.
Ce fichier declare les endpoints pour creer/supprimer des assistants.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db.schema.user import MessageOut, SeedUsersResult, UserInUpdate, UserOutput
from app.service.userService import UserService
from app.util.protectRoute import (
    get_current_user,
    require_admin_or_superadmin,
    require_permissions,
)

users_router = APIRouter()


def get_user_service(session: Session = Depends(get_db)) -> UserService:
    return UserService(session=session)


@users_router.get("/", status_code=200, response_model=list[UserOutput])
def list_users(
    service: UserService = Depends(get_user_service),
    _current_user: UserOutput = Depends(require_admin_or_superadmin),
):
    """
    Liste tous les utilisateurs (admins/superadmins uniquement).
    """
    return service.list_users()


@users_router.put("/me", status_code=200, response_model=UserOutput)
def update_current_user(
    payload: UserInUpdate,
    service: UserService = Depends(get_user_service),
    current_user: UserOutput = Depends(get_current_user),
):
    """
    Met a jour le profil de l'utilisateur courant.
    """
    return service.update_current_user(
        user_details=payload,
        current_user=current_user,
    )


@users_router.delete(
    "/assistants/{user_id}", status_code=200, response_model=MessageOut
)
def delete_assistant(
    user_id: int,
    service: UserService = Depends(get_user_service),
    current_user: UserOutput = Depends(require_permissions("assistants.manage")),
):
    """
    Supprime un assistant (accessible uniquement aux admins et superadmins).
    """
    return service.delete_assistant(
        user_id=user_id,
        current_user=current_user,
    )


@users_router.post("/seed", status_code=200, response_model=SeedUsersResult)
def seed_users(service: UserService = Depends(get_user_service)):
    """
    Cree les utilisateurs par defaut (hors assistants).
    """
    return service.seed_default_users()
