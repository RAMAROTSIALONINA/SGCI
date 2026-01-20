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

ASSISTANT_ROLE = "assistant"


class UserService:
    """
    Regroupe les actions liees aux utilisateurs.
    Ce service utilise un repository pour lire et ecrire dans la base.
    """

    def __init__(self, session: Session):
        self.__userRepository = UserRepository(session=session)

    def signup(self, user_details: UserInCreate) -> UserOutput:
        """
        Inscription d'un nouvel utilisateur.
        Verifie que l'email n'existe pas deja, transforme le mot de passe
        en hash (une version non lisible), puis enregistre l'utilisateur.
        """
        if self.__userRepository.user_exist_by_email(email=user_details.email):
            raise HTTPException(
                status_code=400, detail="User with this email already exists."
            )
        hashed_password = HashHelper.get_password_hash(
            plain_password=user_details.password
        )
        user_details.password = hashed_password
        return self.__userRepository.create_user(
            user_data=user_details,
            role=ASSISTANT_ROLE
        )

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
