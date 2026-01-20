"""
Couche service pour les utilisateurs.
Ici on met la logique metier (les etapes) avant d'appeler la base de donnees.
"""

from sqlalchemy.orm import Session

from fastapi import HTTPException

from app.db.repository.userRepo import UserRepository

from app.db.schema.user import UserOutput, UserInCreate, UserInLogin, UserWithToken

from app.core.security.hashHelper import HashHelper

from app.core.security.authHandler import AuthHandler

import anyio
import secrets

from app.db.repository.twofaRepo import TwoFARepository

from datetime import datetime, timezone, timedelta
from app.service.emailService import send_otp_email

ASSISTANT_ROLE = "assistant"

OPT_TTL_MiNUTES = 5
MAX_OPT_ATTEMPTS = 5


def generate_opt_6_digits() -> str:
    """
    Genere un code OTP a 6 chiffres.
    """
    return f"{secrets.randbelow(1000000):06}"


class UserService:
    """
    Regroupe les actions liees aux utilisateurs.
    Ce service utilise un repository pour lire et ecrire dans la base.
    """

    def __init__(self, session: Session):
        self.__userRepository = UserRepository(session=session)

    def signup(self, user_details: UserInCreate) -> dict:
        """
        Inscription d'un nouvel utilisateur.
        Verifie que l'email n'existe pas deja, transforme le mot de passe
        en hash (une version non lisible), puis enregistre l'utilisateur.
        """
        # verifie si l'email existe deja
        if self.__userRepository.user_exist_by_email(email=user_details.email):
            raise HTTPException(
                status_code=400, detail="User with this email already exists."
            )
        hashed_password = HashHelper.get_password_hash(
            plain_password=user_details.password
        )
        #hash le mot de passe
        user_details.password = hashed_password

        # cree l'utilisateur en base
        user = self.__userRepository.create_user(
            user_data=user_details,
            role=ASSISTANT_ROLE,
            isActive=False,
            isVerified=False
        )

        # genere un code OTP 2FA
        opt = generate_opt_6_digits()
        opt_hash = HashHelper.get_password_hash(opt)
        expired_at = datetime.now(timezone.utc) + timedelta(minutes=OPT_TTL_MiNUTES)

        #stocke le code OTP en base
        TwoFARepository(session=self.__userRepository.session).create_code(
            user_id=user.id,
            code_hash=opt_hash,
            expires_at=expired_at
        )

        try:
            anyio.run(send_otp_email, user.email, opt)
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Unable to send verification email."
            )

        return {"message": "Code envoyer"}
    
    def verify_otp(self, email: str, code: str) -> UserWithToken:
        """
        Verification du code OTP 2FA.
        Verifie que le code est correct et non expire.
        Si oui, marque l'utilisateur comme verifie et actif.
        """
        # recupere l'utilisateur
        user = self.__userRepository.get_user_by_email(email=email)
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )
        
        # recupere le dernier code 2FA valide
        repo_2fa = TwoFARepository(session=self.__userRepository.session)
        code_row = repo_2fa.get_latest_valid_code(user_id=user.id)

        # verifie le code
        if not code_row:
            raise HTTPException(
                status_code=400,
                detail="No valid code found. Please request a new one."
            )
        
        # verifie le nombre de tentatives
        if code_row.attempts >= MAX_OPT_ATTEMPTS:
            raise HTTPException(
                status_code=400,
                detail="Maximum attempts exceeded. Please request a new code."
            )
        
        # verifie la validite du code
        if not HashHelper.verify_password(
            plain_password=code,
            hashed_password=code_row.code_hash
        ):
            repo_2fa.add_attempt(code=code_row)
            raise HTTPException(
                status_code=400,
                detail="Invalid code. Please try again."
            )
        
        # marque le code comme utilise
        repo_2fa.mark_used(code=code_row)

        # marque l'utilisateur comme verifie et actif
        user.is_verified = True
        user.is_active = True
        self.__userRepository.session.commit()
        self.__userRepository.session.refresh(user)
        token = AuthHandler.sign_jwt(user_id=user.id)
        if not token:
            raise HTTPException(
                status_code=500,
                detail="Unable to process request"
            )
        return UserWithToken(token=token)

    def login(self, login_details: UserInLogin) -> UserWithToken:
        """
        Connexion d'un utilisateur.
        Verifie l'email, compare le mot de passe, puis genere un token.
        """
        if not self.__userRepository.user_exist_by_email(
            email=login_details.email
        ):
            raise HTTPException(
                status_code=404,
                detail="Please, create an account.")

        user = self.__userRepository.get_user_by_email(
            email=login_details.email)
        if HashHelper.verify_password(
            plain_password=login_details.password,
            hashed_password=user.password
        ):
            token = AuthHandler.sign_jwt(user_id=user.id)
            if token:
                return UserWithToken(token=token)
            raise HTTPException(
                status_code=500,
                detail="Unable to process request")
        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="User account is inactive."
            )
        if not user.is_verified:
            raise HTTPException(
                status_code=403,
                detail="User account is not verified."
            )
        raise HTTPException(status_code=400, detail="Invalid credentials.")

    def get_user_by_id(self, user_id: int) -> UserOutput:
        """
        Recupere un utilisateur avec son identifiant.
        Si aucun utilisateur n'est trouve, une erreur est levee.
        """
        user = self.__userRepository.get_user_by_id(user_id=user_id)
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )
        return user
