"""
Schemas Pydantic pour les roles.
Ils servent a valider ce qui entre et sort de l'API.
"""

from pydantic import BaseModel


class RoleOutput(BaseModel):
    """
    Donnees renvoyees au client pour un role.
    """

    id: int
    code: str
    name: str
    description: str | None = None
    level: int
    is_system: bool
    is_assistant: bool
    created_by_id: int | None = None

    class Config:
        from_attributes = True


class PermissionOutput(BaseModel):
    """
    Donnees renvoyees au client pour une permission.
    """

    id: int
    code: str
    name: str
    description: str | None = None
    module: str | None = None
    is_system: bool

    class Config:
        from_attributes = True


class RoleWithPermissionsOutput(BaseModel):
    """
    Donnees renvoyees pour un role avec ses permissions.
    """

    id: int
    code: str
    name: str
    description: str | None = None
    level: int
    is_system: bool
    is_assistant: bool
    created_by_id: int | None = None
    permissions: list[PermissionOutput]

    class Config:
        from_attributes = True


class RoleCreate(BaseModel):
    """
    Donnees attendues pour creer un role (assistant).
    """

    code: str
    name: str
    description: str | None = None
    level: int = 6
    permission_codes: list[str] = []
    is_assistant: bool = True


class RolePermissionsUpdate(BaseModel):
    """
    Donnees attendues pour remplacer les permissions d'un role.
    """

    permission_codes: list[str]


class RoleUpdate(BaseModel):
    """
    Donnees attendues pour mettre a jour un role (assistant).
    """

    name: str | None = None
    description: str | None = None
    permission_codes: list[str] | None = None


class SeedRolesResult(BaseModel):
    """
    Statut apres insertion/maj des roles par defaut.
    """

    created: int
    updated: int
