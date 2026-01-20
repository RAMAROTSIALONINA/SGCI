"""
Utilitaires JWT pour l'authentification.
On cree un token signe et on peut le decoder.
"""

import time
import jwt
from decouple import config

JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM = config("JWT_ALGORITHM")


class AuthHandler(object):
    """
    Regroupe les methodes statiques pour gerer les tokens JWT.
    """

    @staticmethod
    def sign_jwt(user_id: int):
        """
        Cree un token JWT simple pour un utilisateur.
        Le token contient l'id utilisateur et une date d'expiration courte.
        """
        payload = {
            "user_id": user_id,
            "expires": time.time() + 900
        }

        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return token

    @staticmethod
    def decode_jwt(token: str) -> dict:
        """
        Decode un token JWT et verifie qu'il n'est pas expire.
        Renvoie le contenu du token ou un dict vide.
        """
        try:
            decoded_token = jwt.decode(
                token, JWT_SECRET, algorithms=[JWT_ALGORITHM]
            )
            return decoded_token if decoded_token["expires"] >= time.time() else {}
        except jwt.ExpiredSignatureError:
            print("unable to decode jwt")
