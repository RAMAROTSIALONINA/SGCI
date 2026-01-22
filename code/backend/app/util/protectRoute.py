"""
Aides pour proteger des routes avec un token.
Ce fichier expose une dependance FastAPI qui recupere l'utilisateur courant.
"""

from typing import Annotated, Union

from fastapi import Depends, Header, HTTPException, status

from sqlalchemy.orm import Session

from app.core.security.authHandler import AuthHandler

from app.service.userService import UserService
from app.service.roleService import RoleService, is_superadmin_role

from app.core.database import get_db

from app.db.schema.user import UserOutput

AUTH_PREFIX = 'Bearer '

ADMIN_ROLE_KEYS = {
    "admin",
    "admin_ubs",
    "admin_c2a",
    "admin_site",
    "admin_acr",
    "superadmin",
    "super_admin",
}


def normalize_role(role: str | None) -> str:
    """
    Normalise un role pour la comparaison (minuscule, espaces -> underscore).
    """
    if not role:
        return ""
    return role.strip().lower().replace(" ", "_")


def get_current_user(
    session: Session = Depends(get_db),  # makany @ base de donnee
    authorization: Annotated[Union[str, None], Header()] = None  # Mijery hoe ao ve le authorization 
) -> UserOutput:
    """
    Lit l'entete Authorization, verifie le token, et retourne l'utilisateur.
    Si le token manque ou est invalide, renvoie une erreur 401.
    """
    auth_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid Authentication Credentials",
    )
    if not authorization:
        raise auth_exception

    if not authorization.startswith(AUTH_PREFIX):
        raise auth_exception

    payload = AuthHandler.decode_jwt(token=authorization[len(AUTH_PREFIX):])

    if payload and payload["user_id"]:
        try:
            user = UserService(session=session).get_user_by_id(payload["user_id"])
            return UserOutput(
                id=user.id,
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                role=user.role
            )
        except Exception as e:
            raise e
    raise auth_exception


def require_admin_or_superadmin(
    user: UserOutput = Depends(get_current_user),
) -> UserOutput:
    """
    Verifie que l'utilisateur courant est admin ou superadmin.
    """
    role_key = normalize_role(user.role)
    if role_key not in ADMIN_ROLE_KEYS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not allowed to perform this action.",
        )
    return user


def require_permissions(*permission_codes: str):
    """
    Verifie que l'utilisateur courant possede toutes les permissions demandees.
    """
    def dependency(
        user: UserOutput = Depends(get_current_user),
        session: Session = Depends(get_db),
    ) -> UserOutput:
        if is_superadmin_role(user.role):
            return user
        role_service = RoleService(session=session)
        user_permissions = role_service.get_role_permission_codes(user.role)
        missing = [code for code in permission_codes if code not in user_permissions]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not allowed to perform this action.",
            )
        return user

    return dependency
