"""
Routes HTTP pour la gestion des roles.
Ce fichier declare les endpoints pour lire et initialiser les roles.
"""
from fastapi import APIRouter, Depends

from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db.schema.role import (
    PermissionOutput,
    RoleCreate,
    RoleOutput,
    RolePermissionsUpdate,
    RoleWithPermissionsOutput,
    SeedRolesResult,
)
from app.service.roleService import RoleService
from app.util.protectRoute import require_permissions
from app.db.schema.user import UserOutput

roles_router = APIRouter()


@roles_router.get("/", status_code=200, response_model=list[RoleOutput])
def list_roles(session: Session = Depends(get_db)):
    """
    Liste les roles existants en base.
    """
    roles = RoleService(session=session).list_roles()
    return [
        {
            "id": role.id,
            "code": role.code,
            "name": role.name,
            "description": role.description,
            "level": role.level,
            "is_system": role.is_system,
            "is_assistant": role.is_assistant,
        }
        for role in roles
    ]


@roles_router.post("/seed", status_code=200, response_model=SeedRolesResult)
def seed_roles(
    session: Session = Depends(get_db),
    _current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Cree ou met a jour les roles par defaut.
    """
    return RoleService(session=session).seed_roles()


@roles_router.get("/permissions", status_code=200, response_model=list[PermissionOutput])
def list_permissions(
    session: Session = Depends(get_db),
    _current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Liste toutes les permissions connues.
    """
    return RoleService(session=session).list_permissions()


@roles_router.get(
    "/assignable-permissions",
    status_code=200,
    response_model=list[PermissionOutput],
)
def list_assignable_permissions(
    session: Session = Depends(get_db),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Liste les permissions assignables par l'utilisateur courant.
    """
    service = RoleService(session=session)
    codes = service.get_assignable_permission_codes(current_user.role)
    permissions = service.list_permissions()
    return [permission for permission in permissions if permission.code in codes]


@roles_router.get(
    "/{role_code}/permissions",
    status_code=200,
    response_model=list[PermissionOutput],
)
def get_role_permissions(
    role_code: str,
    session: Session = Depends(get_db),
    _current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Liste les permissions associees a un role.
    """
    return RoleService(session=session).list_role_permissions(role_code=role_code)


@roles_router.post("/", status_code=201, response_model=RoleWithPermissionsOutput)
def create_role(
    payload: RoleCreate,
    session: Session = Depends(get_db),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Cree un role non systeme (assistant).
    """
    service = RoleService(session=session)
    role = service.create_role(
        role_data=payload.model_dump(),
        creator_role=current_user.role,
    )
    permissions = service.list_role_permissions(role_code=role.code)
    return {
        "id": role.id,
        "code": role.code,
        "name": role.name,
        "description": role.description,
        "level": role.level,
        "is_system": role.is_system,
        "is_assistant": role.is_assistant,
        "permissions": permissions,
    }


@roles_router.put(
    "/{role_code}/permissions",
    status_code=200,
    response_model=RoleWithPermissionsOutput,
)
def update_role_permissions(
    role_code: str,
    payload: RolePermissionsUpdate,
    session: Session = Depends(get_db),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Remplace les permissions d'un role.
    """
    service = RoleService(session=session)
    role = service.set_role_permissions(
        role_code=role_code,
        permission_codes=payload.permission_codes,
        creator_role=current_user.role,
    )
    permissions = service.list_role_permissions(role_code=role.code)
    return {
        "id": role.id,
        "code": role.code,
        "name": role.name,
        "description": role.description,
        "level": role.level,
        "is_system": role.is_system,
        "is_assistant": role.is_assistant,
        "permissions": permissions,
    }
