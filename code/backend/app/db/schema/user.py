"""
Schemas Pydantic pour les donnees utilisateur.
Ils servent a valider ce qui entre et sort de l'API.
"""

from typing import Union

from pydantic import BaseModel, EmailStr


class UserInCreate(BaseModel):
    """
    Donnees attendues pour creer un compte utilisateur.
    """

    first_name: str
    last_name: str
    email: EmailStr
    password: str
    role_code: str | None = None


class UserOutput(BaseModel):
    """
    Donnees renvoyees au client quand on retourne un utilisateur.
    """

    id: int
    first_name: str
    last_name: str
    email: EmailStr
    role: str
    created_by_id: int | None = None
    theme_mode: str | None = None
    palette: str | None = None


class UserInUpdate(BaseModel):
    """
    Champs optionnels pour mettre a jour un utilisateur existant.
    """

    first_name: Union[str, None] = None
    last_name: Union[str, None] = None
    email: Union[EmailStr, None] = None
    current_password: Union[str, None] = None
    password: Union[str, None] = None
    theme_mode: Union[str, None] = None
    palette: Union[str, None] = None


class UserInLogin(BaseModel):
    """
    Donnees attendues pour se connecter (email et mot de passe).
    """

    email: EmailStr
    password: str


class UserWithToken(BaseModel):
    """
    Reponse apres connexion: tokens d'acces et de rafraichissement.
    """

    access_token: str
    refresh_token: str


class RefreshTokenIn(BaseModel):
    """
    Donnee attendue pour rafraichir un token d'acces.
    """

    refresh_token: str


class MessageOut(BaseModel):
    """
    Schema pour les messages simples.
    Utile pour les reponses d'API.
    """

    message: str


class VerifyOtpIn(BaseModel):
    """
    Donnees attendues pour verifier un code 2FA.
    """

    email: EmailStr
    code: str


class ResendOtpIn(BaseModel):
    """
    Donnees attendues pour renvoyer un code 2FA.
    """

    email: EmailStr


class SeedUsersResult(BaseModel):
    """
    Statut apres insertion des utilisateurs par defaut.
    """

    created: int
    skipped: int
