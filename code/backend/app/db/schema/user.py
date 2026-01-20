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


class UserOutput(BaseModel):
    """
    Donnees renvoyees au client quand on retourne un utilisateur.
    """
    id: int
    first_name: str
    last_name: str
    email: EmailStr
    role: str


class UserInUpdate(BaseModel):
    """
    Champs optionnels pour mettre a jour un utilisateur existant.
    """
    first_name: Union[str, None] = None
    last_name: Union[str, None] = None
    email: Union[EmailStr, None] = None
    password: Union[str, None] = None


class UserInLogin(BaseModel):
    """
    Donnees attendues pour se connecter (email et mot de passe).
    """
    email: EmailStr
    password: str


class UserWithToken(BaseModel):
    """
    Reponse apres connexion: un token d'acces.
    """
    token: str
