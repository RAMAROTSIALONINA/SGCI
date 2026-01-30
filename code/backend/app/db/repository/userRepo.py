"""
Acces aux donnees pour les utilisateurs.
Ici on lit et on ecrit dans la table User.
"""

from app.db.models.user import User
from app.db.schema.user import UserInCreate
from fastapi import HTTPException

from .base import BaseRepository


class UserRepository(BaseRepository):
    """
    Fournit des operations simples pour la table User.
    """

    def _build_user(
        self,
        user_data: UserInCreate,
        role: str | None = None,
        is_active: bool = False,
        is_verified: bool = False,
        created_by_id: int | None = None,
    ) -> User:
        payload = user_data.model_dump(exclude_none=True, exclude={"role_code"})
        if role is not None:
            payload["role"] = role
        if created_by_id is not None:
            payload["created_by_id"] = created_by_id
        payload["is_active"] = is_active
        payload["is_verified"] = is_verified
        return User(**payload)

    def add_user(
        self,
        user_data: UserInCreate,
        role: str | None = None,
        is_active: bool = False,
        is_verified: bool = False,
        created_by_id: int | None = None,
    ) -> User:
        """
        Ajoute un utilisateur a la session sans commit immediat.
        """
        new_user = self._build_user(
            user_data=user_data,
            role=role,
            is_active=is_active,
            is_verified=is_verified,
            created_by_id=created_by_id,
        )
        self.session.add(new_user)
        return new_user

    def create_user(
        self,
        user_data: UserInCreate,
        role: str | None = None,
        is_active: bool = False,
        is_verified: bool = False,
        created_by_id: int | None = None,
    ) -> User:
        """
        Cree un utilisateur en base a partir des donnees recues.
        La methode enregistre, commit, puis renvoie l'objet cree.
        """
        new_user = self._build_user(
            user_data=user_data,
            role=role,
            is_active=is_active,
            is_verified=is_verified,
            created_by_id=created_by_id,
        )
        return self._save(new_user)

    def exists_by_email(self, email: str) -> bool:
        """
        Indique si un utilisateur avec cet email existe deja.
        """
        return (
            self.session.query(User.id).filter(User.email == email).first() is not None
        )

    def exists_by_id(self, user_id: int) -> bool:
        """
        Indique si un utilisateur avec cet identifiant existe deja.
        """
        return (
            self.session.query(User.id).filter(User.id == user_id).first() is not None
        )

    def get_by_email(self, email: str) -> User | None:
        """
        Recupere un utilisateur par email, ou None s'il n'existe pas.
        """
        return self.session.query(User).filter(User.email == email).first()

    def get_by_id(self, user_id: int) -> User | None:
        """
        Recupere un utilisateur par identifiant, ou None s'il n'existe pas.
        """
        return self.session.query(User).filter_by(id=user_id).first()

    def get_by_id_or_404(
        self,
        user_id: int,
        *,
        detail: str = "User not found.",
    ) -> User:
        """
        Recupere un utilisateur ou leve une HTTPException 404.
        """
        user = self.get_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail=detail)
        return user

    def get_by_email_or_404(
        self,
        email: str,
        *,
        detail: str = "User not found.",
    ) -> User:
        """
        Recupere un utilisateur ou leve une HTTPException 404.
        """
        user = self.get_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail=detail)
        return user

    def delete_user(self, user: User) -> None:
        """
        Supprime un utilisateur existant.
        """
        self._delete(user)

    def update_user(self, user: User, updates: dict) -> User:
        """
        Met a jour un utilisateur avec les champs fournis.
        """
        for field, value in updates.items():
            setattr(user, field, value)
        return self._save(user)

    def list_users(self) -> list[User]:
        """
        Liste tous les utilisateurs en base.
        """
        return self.session.query(User).order_by(User.id.asc()).all()
