"""
Routes HTTP pour l'authentification.
Ce fichier declare les endpoints FastAPI pour se connecter (login)
et creer un compte (signup).
"""

from typing import Union

from app.core.database import get_db
from app.core.security.authHandler import AuthHandler
from app.db.schema.user import (
    MessageOut,
    RefreshTokenIn,
    ResendOtpIn,
    UserInCreate,
    UserInLogin,
    UserOutput,
    UserWithToken,
    VerifyOtpIn,
)
from app.service.userService import UserService
from app.util.protectRoute import require_permissions
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

auth_router = APIRouter()


def get_user_service(session: Session = Depends(get_db)) -> UserService:
    return UserService(session=session)


@auth_router.post(
    "/login", status_code=200, response_model=Union[UserWithToken, MessageOut]
)
def login(
    login_details: UserInLogin,
    service: UserService = Depends(get_user_service),
):
    """
    Recoit un email et un mot de passe pour une connexion.
    Si les identifiants sont bons, renvoie un token (ou un OTP pour un assistant).
    """
    return service.login(login_details=login_details)


@auth_router.post("/signup", status_code=201, response_model=MessageOut)
def signup(
    signup_details: UserInCreate,
    service: UserService = Depends(get_user_service),
    _current_user: UserOutput = Depends(require_permissions("assistants.manage")),
):
    """
    Recoit les informations d'inscription et cree un utilisateur.
    Si tout se passe bien, renvoie les donnees du nouvel utilisateur.
    """
    return service.signup(
        user_details=signup_details,
        current_user=_current_user,
    )


@auth_router.post("/verify-otp", status_code=200, response_model=UserWithToken)
def verify_otp(
    payload: VerifyOtpIn,
    service: UserService = Depends(get_user_service),
):
    """
    Recoit un email et un code OTP pour verification 2FA.
    Si le code est valide, renvoie un token de connexion.
    """
    return service.verify_otp(
        email=payload.email,
        code=payload.code,
    )


@auth_router.post("/refresh", status_code=200, response_model=UserWithToken)
def refresh_token(
    payload: RefreshTokenIn,
    service: UserService = Depends(get_user_service),
):
    """
    Recoit un refresh token et renvoie un nouveau couple de tokens.
    """
    auth_payload = AuthHandler.decode_jwt(
        token=payload.refresh_token,
        expected_type="refresh",
    )
    if not auth_payload or not auth_payload.get("user_id"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )
    return service.refresh_tokens(user_id=auth_payload["user_id"])


@auth_router.post("/resend-otp", status_code=200, response_model=MessageOut)
def resend_otp(
    payload: ResendOtpIn,
    service: UserService = Depends(get_user_service),
):
    """
    Recoit un email et renvoie un nouveau code OTP a l'assistant.
    """
    return service.resend_otp(email=payload.email)
