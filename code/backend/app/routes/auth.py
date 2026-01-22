"""
Routes HTTP pour l'authentification.
Ce fichier declare les endpoints FastAPI pour se connecter (login)
et creer un compte (signup).
"""
from typing import Union

from fastapi import APIRouter, Depends

from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db.schema.user import (
    MessageOut,
    UserInCreate,
    UserInLogin,
    UserOutput,
    UserWithToken,
    VerifyOtpIn,
)
from app.service.userService import UserService
from app.util.protectRoute import require_permissions

auth_router = APIRouter()


@auth_router.post("/login", status_code=200, response_model=Union[UserWithToken, MessageOut])
def login(login_details: UserInLogin, session: Session = Depends(get_db)):
    """
    Recoit un email et un mot de passe pour une connexion.
    Si les identifiants sont bons, renvoie un token (ou un OTP pour un assistant).
    """
    try:
        return UserService(session=session).login(login_details=login_details)
    except Exception as e:
        print(e)
        raise e
    return {"data": login_details}


@auth_router.post("/signup", status_code=201, response_model=MessageOut)
def signup(
    signup_details: UserInCreate,
    session: Session = Depends(get_db),
    _current_user: UserOutput = Depends(require_permissions("assistants.manage")),
):
    """
    Recoit les informations d'inscription et cree un utilisateur.
    Si tout se passe bien, renvoie les donnees du nouvel utilisateur.
    """
    try:
        return UserService(session=session).signup(
            user_details=signup_details,
            current_user=_current_user,
        )
    except Exception as e:
        print(e)
        raise e
    return {"data": signup_details}

@auth_router.post("/verify-otp", status_code=200, response_model=UserWithToken)
def verify_otp(payload: VerifyOtpIn, session: Session = Depends(get_db)):
    """
    Recoit un email et un code OTP pour verification 2FA.
    Si le code est valide, renvoie un token de connexion.
    """
    try:
        return UserService(session=session).verify_otp(email=payload.email, code=payload.code)
    except Exception as e:
        print(e)
        raise e
    return {"data": payload}
