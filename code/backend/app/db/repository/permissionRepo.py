"""
Acces aux donnees pour les permissions.
Ici on lit et on ecrit dans la table Permission et RolePermissions.
"""
from sqlalchemy import delete

from app.db.models.permission import Permission
from app.db.models.role_permission import RolePermission

from .base import BaseRepository


class PermissionRepository(BaseRepository):
    """
    Fournit des operations simples pour les permissions.
    """
    def list_permissions(self) -> list[Permission]:
        """
        Recupere toutes les permissions.
        """
        return (
            self.session.query(Permission)
            .order_by(Permission.module.asc(), Permission.code.asc())
            .all()
        )

    def get_by_code(self, code: str) -> Permission | None:
        """
        Recupere une permission par code, ou None si absente.
        """
        return self.session.query(Permission).filter(Permission.code == code).first()

    def get_by_codes(self, codes: list[str]) -> list[Permission]:
        """
        Recupere les permissions correspondant aux codes donnes.
        """
        if not codes:
            return []
        return self.session.query(Permission).filter(Permission.code.in_(codes)).all()

    def add_permission(self, permission_data: dict) -> Permission:
        """
        Ajoute une permission a la session sans commit immediat.
        """
        permission = Permission(**permission_data)
        self.session.add(permission)
        return permission

    def list_permissions_for_role(self, role_id: int) -> list[Permission]:
        """
        Recupere les permissions associees a un role.
        """
        return (
            self.session.query(Permission)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .filter(RolePermission.role_id == role_id)
            .order_by(Permission.module.asc(), Permission.code.asc())
            .all()
        )

    def set_role_permissions(self, role_id: int, permission_ids: list[int]) -> None:
        """
        Remplace la liste des permissions associees a un role.
        """
        self.session.execute(
            delete(RolePermission).where(RolePermission.role_id == role_id)
        )
        for permission_id in permission_ids:
            self.session.add(
                RolePermission(role_id=role_id, permission_id=permission_id)
            )
