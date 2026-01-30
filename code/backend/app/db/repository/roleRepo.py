"""
Acces aux donnees pour les roles.
Ici on lit et on ecrit dans la table Role.
"""

from app.db.models.role import Role
from fastapi import HTTPException

from .base import BaseRepository


class RoleRepository(BaseRepository):
    """
    Fournit des operations simples pour la table Role.
    """

    def list_roles(self) -> list[Role]:
        """
        Recupere tous les roles tries par niveau.
        """
        return self.session.query(Role).order_by(Role.level.asc()).all()

    def get_by_code(self, code: str) -> Role | None:
        """
        Recupere un role par son code, ou None s'il n'existe pas.
        """
        return self.session.query(Role).filter(Role.code == code).first()

    def get_by_code_or_404(
        self,
        code: str,
        *,
        detail: str = "Role not found.",
    ) -> Role:
        """
        Recupere un role ou leve une HTTPException 404.
        """
        role = self.get_by_code(code)
        if not role:
            raise HTTPException(status_code=404, detail=detail)
        return role

    def get_by_id(self, role_id: int) -> Role | None:
        """
        Recupere un role par son identifiant, ou None s'il n'existe pas.
        """
        return self.session.query(Role).filter(Role.id == role_id).first()

    def get_by_id_or_404(
        self,
        role_id: int,
        *,
        detail: str = "Role not found.",
    ) -> Role:
        """
        Recupere un role ou leve une HTTPException 404.
        """
        role = self.get_by_id(role_id)
        if not role:
            raise HTTPException(status_code=404, detail=detail)
        return role

    def exists_by_code(self, code: str) -> bool:
        """
        Indique si un role avec ce code existe.
        """
        return self.session.query(Role.id).filter(Role.code == code).first() is not None

    def exists_by_id(self, role_id: int) -> bool:
        """
        Indique si un role avec cet identifiant existe.
        """
        return (
            self.session.query(Role.id).filter(Role.id == role_id).first() is not None
        )

    def add_role(self, role_data: dict) -> Role:
        """
        Ajoute un role a la session sans commit immediat.
        """
        role = Role(**role_data)
        self.session.add(role)
        return role

    def create_role(self, role_data: dict) -> Role:
        """
        Cree un role en base avec commit immediat.
        """
        role = Role(**role_data)
        return self._save(role)

    def delete_role(self, role: Role) -> None:
        """
        Supprime un role.
        """
        self._delete(role)
