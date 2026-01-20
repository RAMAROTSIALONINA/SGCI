"""
Routes HTTP pour l'authentification.
Ce fichier declare les endpoints FastAPI pour se connecter (login)
et creer un compte (signup).
"""
from fastapi import APIRouter, Depends

from sqlalchemy.orm import Session

from app.db.schema.user import UserInLogin, UserInCreate, UserOutput, UserWithToken

from app.core.database import get_db

from app.service.userService import UserService

auth_router = APIRouter()


@auth_router.post("/login", status_code=200, response_model=UserWithToken)
def login(login_details: UserInLogin, session: Session = Depends(get_db)):
    """
    Recoit un email et un mot de passe pour une connexion.
    Si les identifiants sont bons, renvoie un token de connexion.
    """
    try:
        return UserService(session=session).login(login_details=login_details)
    except Exception as e:
        print(e)
        raise e
    return {"data": login_details}


@auth_router.post("/signup", status_code=201, response_model=UserOutput)
def signup(signup_details: UserInCreate, session: Session = Depends(get_db)):
    """
    Recoit les informations d'inscription et cree un utilisateur.
    Si tout se passe bien, renvoie les donnees du nouvel utilisateur.
    """
    try:
        return UserService(session=session).signup(user_details=signup_details)
    except Exception as e:
        print(e)
        raise e
    return {"data": signup_details}
