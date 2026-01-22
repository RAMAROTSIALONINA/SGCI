"""
Acces aux donnees pour les utilisateurs.
Ici on lit et on ecrit dans la table User.
"""

from app.db.models.user import User

from app.db.schema.user import UserInCreate

from .base import BaseRepository


class UserRepository(BaseRepository):
    """
    Fournit des operations simples pour la table User.
    """
    def create_user(
        self,
        user_data: UserInCreate,
        role: str | None = None,
        isActive: bool = False,
        isVerified: bool = False,
        created_by_id: int | None = None,
    ) -> User:
        """
        Cree un utilisateur en base a partir des donnees recues.
        La methode enregistre, commit, puis renvoie l'objet cree.
        """
        payload = user_data.model_dump(exclude_none=True, exclude={"role_code"})
        if role is not None:
            payload["role"] = role
        if created_by_id is not None:
            payload["created_by_id"] = created_by_id
        payload["is_active"] = isActive
        payload["is_verified"] = isVerified
        new_user = User(**payload)
        self.session.add(instance=new_user)
        self.session.commit()
        self.session.refresh(instance=new_user)
        return new_user

    def user_exist_by_email(self, email: str) -> bool:
        """
        Indique si un utilisateur avec cet email existe deja.
        """
        user = self.session.query(User).filter(User.email == email).first()
        return bool(user)

    def get_user_by_email(self, email: str) -> User | None:
        """
        Recupere un utilisateur par email, ou None s'il n'existe pas.
        """
        user = self.session.query(User).filter(User.email == email).first()
        return user

    def get_user_by_id(self, user_id: int) -> User | None:
        """
        Recupere un utilisateur par identifiant, ou None s'il n'existe pas.
        """
        user = self.session.query(User).filter_by(id=user_id).first()
        return user

    def delete_user(self, user: User) -> None:
        """
        Supprime un utilisateur existant.
        """
        self.session.delete(user)
        self.session.commit()

    def list_users(self) -> list[User]:
        """
        Liste tous les utilisateurs en base.
        """
        return self.session.query(User).order_by(User.id.asc()).all()
