"""
Acces aux donnees pour les preferences utilisateur.
"""

from app.db.models.user_preference import UserPreference
from fastapi import HTTPException

from .base import BaseRepository


class UserPreferenceRepository(BaseRepository):
    """
    Fournit des operations simples pour UserPreferences.
    """

    def add_preference(
        self,
        user_id: int,
        theme_mode: str | None = None,
        palette: str | None = None,
    ) -> UserPreference:
        """
        Ajoute une preference utilisateur sans commit immediat.
        """
        preference = UserPreference(
            user_id=user_id,
            theme_mode=theme_mode,
            palette=palette,
        )
        self.session.add(preference)
        return preference

    def create_preference(
        self,
        user_id: int,
        theme_mode: str | None = None,
        palette: str | None = None,
    ) -> UserPreference:
        """
        Cree une preference utilisateur avec commit immediat.
        """
        preference = self.add_preference(
            user_id=user_id,
            theme_mode=theme_mode,
            palette=palette,
        )
        return self._save(preference)

    def get_by_user_id(self, user_id: int) -> UserPreference | None:
        """
        Recupere les preferences d'un utilisateur.
        """
        return (
            self.session.query(UserPreference)
            .filter(UserPreference.user_id == user_id)
            .first()
        )

    def get_by_user_id_or_404(
        self,
        user_id: int,
        *,
        detail: str = "User preferences not found.",
    ) -> UserPreference:
        """
        Recupere les preferences ou leve une HTTPException 404.
        """
        preference = self.get_by_user_id(user_id=user_id)
        if not preference:
            raise HTTPException(status_code=404, detail=detail)
        return preference

    def exists_by_user_id(self, user_id: int) -> bool:
        """
        Indique si des preferences existent pour un utilisateur.
        """
        return (
            self.session.query(UserPreference.id)
            .filter(UserPreference.user_id == user_id)
            .first()
            is not None
        )

    def upsert_preferences(
        self,
        user_id: int,
        theme_mode: str | None = None,
        palette: str | None = None,
    ) -> UserPreference:
        """
        Cree ou met a jour les preferences d'apparence.
        """
        preference = self.get_by_user_id(user_id=user_id)
        if not preference:
            preference = UserPreference(user_id=user_id)
            self.session.add(preference)

        if theme_mode is not None:
            preference.theme_mode = theme_mode
        if palette is not None:
            preference.palette = palette

        return self._save(preference)
