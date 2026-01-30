"""
Utilitaires et constantes pour les utilisateurs.
"""

import secrets

ASSISTANT_ROLE = "assistant"
DEFAULT_SEED_PASSWORD = "Admin123!"
DEFAULT_USER_SEEDS = [
    {
        "first_name": "MrFabrice",
        "last_name": "Fabrice",
        "email": "superadmin@sgci.com",
        "role": "super_admin",
    },
    {
        "first_name": "MrJao",
        "last_name": "Jao",
        "email": "admin.ubs@sgci.com",
        "role": "admin_ubs",
    },
    {
        "first_name": "MmeSalohy",
        "last_name": "Salohy",
        "email": "admin.c2a@sgci.com",
        "role": "admin_c2a",
    },
    {
        "first_name": "Mr Ratovo",
        "last_name": "Ratovo",
        "email": "admin.site@sgci.com",
        "role": "admin_site",
    },
    {
        "first_name": "Helene",
        "last_name": "Morel",
        "email": "admin.acr@sgci.com",
        "role": "admin_acr",
    },
]

OTP_TTL_MINUTES = 5
MAX_OTP_ATTEMPTS = 5


def generate_otp_6_digits() -> str:
    """
    Genere un code OTP a 6 chiffres.
    """
    return f"{secrets.randbelow(1000000):06}"