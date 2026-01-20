"""
Table pour le repository des codes 2FA.
Ici on lit et on ecrit dans la table TwoFACodes.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models.twofa_code import TwoFACode


class TwoFARepository:
    """
    Fournit des operations simples pour la table TwoFACodes.
    """
    def __init__(self, session: Session):
        self.session = session
    
    def create_code(self, user_id: int, code_hash: str, expires_at):
        """
        Cree un code 2FA en base a partir des donnees recues.
        La methode enregistre, commit, puis renvoie l'objet cree.
        """

        new_code = TwoFACode(
            user_id=user_id,
            code_hash=code_hash,
            expires_at=expires_at
        )
        self.session.add(new_code)
        self.session.commit()
        self.session.refresh(new_code)
        return new_code
    
    def get_latest_valid_code(self, user_id: int):
        """
        Recupere le dernier code 2FA valide pour un utilisateur.
        Un code est valide s'il n'est pas utilise et qu'il n'a pas expire.
        """
        now = datetime.now(timezone.utc)
        code = (
            self.session.query(TwoFACode)
            .filter(
                TwoFACode.user_id == user_id,
                TwoFACode.used_at == None,
                TwoFACode.expires_at > now
            )
            .order_by(TwoFACode.created_at.desc())
            .first()
        )
        return code
    
    def mark_used(self, code: TwoFACode):
        """
        Marque un code 2FA comme utilise en mettant a jour used_at.
        """
        code.used_at = datetime.now(timezone.utc)
        self.session.commit()
        self.session.refresh(code)
        return code
    
    def add_attempt(self, code: TwoFACode):
        """
        Incremente le nombre de tentatives pour un code 2FA.
        """
        code.attempts += 1
        self.session.commit()
        self.session.refresh(code)
        return code
