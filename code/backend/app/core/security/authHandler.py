"""
Utilitaires JWT pour l'authentification.
On cree un token signe et on peut le decoder.
"""

import time

import jwt
from decouple import config

JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM = config("JWT_ALGORITHM", default="HS256")
JWT_ACCESS_TTL_SECONDS = config(
    "JWT_ACCESS_TTL_SECONDS",
    default=config("JWT_TTL_SECONDS", default=900, cast=int),
    cast=int,
)
JWT_REFRESH_TTL_SECONDS = config(
    "JWT_REFRESH_TTL_SECONDS",
    default=2592000,
    cast=int,
)


class AuthHandler(object):
    """
    Regroupe les methodes statiques pour gerer les tokens JWT.
    """

    @staticmethod
    def sign_jwt(user_id: int):
        """
        Cree un token JWT d'acces (compatibilite avec l'ancien nom).
        """
        return AuthHandler.sign_access_jwt(user_id=user_id)

    @staticmethod
    def sign_access_jwt(user_id: int) -> str:
        """
        Cree un token JWT d'acces pour un utilisateur.
        """
        return AuthHandler._sign_token(
            user_id=user_id,
            token_type="access",
            ttl_seconds=JWT_ACCESS_TTL_SECONDS,
        )

    @staticmethod
    def sign_refresh_jwt(user_id: int) -> str:
        """
        Cree un token JWT de rafraichissement pour un utilisateur.
        """
        return AuthHandler._sign_token(
            user_id=user_id,
            token_type="refresh",
            ttl_seconds=JWT_REFRESH_TTL_SECONDS,
        )

    @staticmethod
    def _sign_token(user_id: int, token_type: str, ttl_seconds: int) -> str:
        issued_at = int(time.time())
        expires_at = issued_at + ttl_seconds
        payload = {
            "user_id": user_id,
            "token_type": token_type,
            "iat": issued_at,
            "expires": expires_at,
            "exp": expires_at,
        }

        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    @staticmethod
    def decode_jwt(token: str, expected_type: str | None = None) -> dict:
        """
        Decode un token JWT et verifie qu'il n'est pas expire.
        Si expected_type est fourni, verifie aussi le type de token.
        Renvoie le contenu du token ou un dict vide.
        """
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            exp_value = decoded_token.get("exp") or decoded_token.get("expires")
            if exp_value is None:
                return {}
            if expected_type:
                token_type = decoded_token.get("token_type")
                if token_type != expected_type:
                    return {}
            return decoded_token if exp_value >= time.time() else {}
        except jwt.ExpiredSignatureError:
            return {}
        except jwt.InvalidTokenError:
            return {}
