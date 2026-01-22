"""
Routes HTTP pour la gestion des utilisateurs.
Ce fichier declare les endpoints pour creer/supprimer des assistants.
"""
from fastapi import APIRouter, Depends

from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db.schema.user import MessageOut, SeedUsersResult, UserOutput
from app.service.userService import UserService
from app.util.protectRoute import require_admin_or_superadmin, require_permissions

users_router = APIRouter()


@users_router.get("/", status_code=200, response_model=list[UserOutput])
def list_users(
    session: Session = Depends(get_db),
    _current_user: UserOutput = Depends(require_admin_or_superadmin),
):
    """
    Liste tous les utilisateurs (admins/superadmins uniquement).
    """
    return UserService(session=session).list_users()


@users_router.delete("/assistants/{user_id}", status_code=200, response_model=MessageOut)
def delete_assistant(
    user_id: int,
    session: Session = Depends(get_db),
    current_user: UserOutput = Depends(require_permissions("assistants.manage")),
):
    """
    Supprime un assistant (accessible uniquement aux admins et superadmins).
    """
    return UserService(session=session).delete_assistant(
        user_id=user_id,
        current_user=current_user,
    )


@users_router.post("/seed", status_code=200, response_model=SeedUsersResult)
def seed_users(session: Session = Depends(get_db)):
    """
    Cree les utilisateurs par defaut (hors assistants).
    """
    return UserService(session=session).seed_default_users()
