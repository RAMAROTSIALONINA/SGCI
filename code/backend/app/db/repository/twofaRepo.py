"""
Table pour le repository des codes 2FA.
Ici on lit et on ecrit dans la table TwoFACodes.
"""

from datetime import datetime, timezone

from app.db.models.twofa_code import TwoFACode
from fastapi import HTTPException

from .base import BaseRepository


class TwoFARepository(BaseRepository):
    """
    Fournit des operations simples pour la table TwoFACodes.
    """

    def add_code(
        self,
        user_id: int,
        code_hash: str,
        expires_at: datetime,
    ) -> TwoFACode:
        """
        Ajoute un code 2FA sans commit immediat.
        """
        new_code = TwoFACode(
            user_id=user_id, code_hash=code_hash, expires_at=expires_at
        )
        self.session.add(new_code)
        return new_code

    def create_code(
        self,
        user_id: int,
        code_hash: str,
        expires_at: datetime,
    ) -> TwoFACode:
        """
        Cree un code 2FA en base a partir des donnees recues.
        La methode enregistre, commit, puis renvoie l'objet cree.
        """

        new_code = self.add_code(
            user_id=user_id,
            code_hash=code_hash,
            expires_at=expires_at,
        )
        return self._save(new_code)

    def get_by_id(self, code_id: int) -> TwoFACode | None:
        """
        Recupere un code 2FA par identifiant.
        """
        return self.session.query(TwoFACode).filter(TwoFACode.id == code_id).first()

    def get_by_id_or_404(
        self,
        code_id: int,
        *,
        detail: str = "2FA code not found.",
    ) -> TwoFACode:
        """
        Recupere un code 2FA ou leve une HTTPException 404.
        """
        code = self.get_by_id(code_id)
        if not code:
            raise HTTPException(status_code=404, detail=detail)
        return code

    def exists_by_id(self, code_id: int) -> bool:
        """
        Indique si un code 2FA existe.
        """
        return (
            self.session.query(TwoFACode.id).filter(TwoFACode.id == code_id).first()
            is not None
        )

    def get_latest_valid_code(self, user_id: int) -> TwoFACode | None:
        """
        Recupere le dernier code 2FA valide pour un utilisateur.
        Un code est valide s'il n'est pas utilise et qu'il n'a pas expire.
        """
        now = datetime.now(timezone.utc)
        code = (
            self.session.query(TwoFACode)
            .filter(
                TwoFACode.user_id == user_id,
                TwoFACode.used_at.is_(None),
                TwoFACode.expires_at > now,
            )
            .order_by(TwoFACode.created_at.desc())
            .first()
        )
        return code

    def mark_used(self, code: TwoFACode) -> TwoFACode:
        """
        Marque un code 2FA comme utilise en mettant a jour used_at.
        """
        code.used_at = datetime.now(timezone.utc)
        return self._save(code)

    def add_attempt(self, code: TwoFACode) -> TwoFACode:
        """
        Incremente le nombre de tentatives pour un code 2FA.
        """
        code.attempts += 1
        return self._save(code)
