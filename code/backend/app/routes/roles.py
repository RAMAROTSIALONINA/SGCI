"""
Routes HTTP pour la gestion des roles.
Ce fichier declare les endpoints pour lire et initialiser les roles.
"""

from app.core.database import get_db
from app.db.schema.role import (
    PermissionOutput,
    RoleCreate,
    RoleOutput,
    RolePermissionsUpdate,
    RoleUpdate,
    RoleWithPermissionsOutput,
    SeedRolesResult,
)
from app.db.schema.user import MessageOut, UserOutput
from app.service.roleService import RoleService
from app.util.protectRoute import require_permissions
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

roles_router = APIRouter()


def get_role_service(session: Session = Depends(get_db)) -> RoleService:
    return RoleService(session=session)


def _role_to_output(role) -> RoleOutput:
    return RoleOutput(
        id=role.id,
        code=role.code,
        name=role.name,
        description=role.description,
        level=role.level,
        is_system=role.is_system,
        is_assistant=role.is_assistant,
        created_by_id=role.created_by_id,
    )


def _role_with_permissions(role, permissions: list[PermissionOutput]):
    return RoleWithPermissionsOutput(
        id=role.id,
        code=role.code,
        name=role.name,
        description=role.description,
        level=role.level,
        is_system=role.is_system,
        is_assistant=role.is_assistant,
        created_by_id=role.created_by_id,
        permissions=permissions,
    )


@roles_router.get("/", status_code=200, response_model=list[RoleOutput])
def list_roles(service: RoleService = Depends(get_role_service)):
    """
    Liste les roles existants en base.
    """
    roles = service.list_roles()
    return [_role_to_output(role) for role in roles]


@roles_router.post("/seed", status_code=200, response_model=SeedRolesResult)
def seed_roles(
    service: RoleService = Depends(get_role_service),
    _current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Cree ou met a jour les roles par defaut.
    """
    return service.seed_roles()


@roles_router.get(
    "/permissions", status_code=200, response_model=list[PermissionOutput]
)
def list_permissions(
    service: RoleService = Depends(get_role_service),
    _current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Liste toutes les permissions connues.
    """
    return service.list_permissions()


@roles_router.get(
    "/assignable-permissions",
    status_code=200,
    response_model=list[PermissionOutput],
)
def list_assignable_permissions(
    service: RoleService = Depends(get_role_service),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Liste les permissions assignables par l'utilisateur courant.
    """
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
    service: RoleService = Depends(get_role_service),
    _current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Liste les permissions associees a un role.
    """
    return service.list_role_permissions(role_code=role_code)


@roles_router.post("/", status_code=201, response_model=RoleWithPermissionsOutput)
def create_role(
    payload: RoleCreate,
    service: RoleService = Depends(get_role_service),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Cree un role non systeme (assistant).
    """
    role = service.create_role(
        role_data=payload.model_dump(),
        creator_role=current_user.role,
        creator_user_id=current_user.id,
    )
    permissions = service.list_role_permissions(role_code=role.code)
    return _role_with_permissions(role, permissions)


@roles_router.put(
    "/{role_code}/permissions",
    status_code=200,
    response_model=RoleWithPermissionsOutput,
)
def update_role_permissions(
    role_code: str,
    payload: RolePermissionsUpdate,
    service: RoleService = Depends(get_role_service),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Remplace les permissions d'un role.
    """
    role = service.set_role_permissions(
        role_code=role_code,
        permission_codes=payload.permission_codes,
        current_user=current_user,
    )
    permissions = service.list_role_permissions(role_code=role.code)
    return _role_with_permissions(role, permissions)


@roles_router.put(
    "/{role_code}",
    status_code=200,
    response_model=RoleWithPermissionsOutput,
)
def update_role(
    role_code: str,
    payload: RoleUpdate,
    service: RoleService = Depends(get_role_service),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Met a jour un role (nom, description, permissions).
    """
    role = service.update_role(
        role_code=role_code,
        updates=payload.model_dump(exclude_none=True),
        current_user=current_user,
    )
    permissions = service.list_role_permissions(role_code=role.code)
    return _role_with_permissions(role, permissions)


@roles_router.delete(
    "/{role_code}",
    status_code=200,
    response_model=MessageOut,
)
def delete_role(
    role_code: str,
    service: RoleService = Depends(get_role_service),
    current_user: UserOutput = Depends(require_permissions("roles.manage")),
):
    """
    Supprime un role non systeme.
    """
    service.delete_role(
        role_code=role_code,
        current_user=current_user,
    )
    return {"message": "Role deleted."}
