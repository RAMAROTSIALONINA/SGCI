"""
Utilitaires communs pour la gestion des roles.
"""

SUPERADMIN_ROLE_KEYS = {"superadmin", "super_admin"}
ADMIN_ROLE_KEYS = {
    "admin",
    "admin_ubs",
    "admin_c2a",
    "admin_site",
    "admin_acr",
    "superadmin",
    "super_admin",
}


def normalize_role(role: str | None) -> str:
    """
    Normalise un role pour la comparaison (minuscule, espaces -> underscore).
    """
    if not role:
        return ""
    return role.strip().lower().replace(" ", "_")


def is_superadmin_role(role: str | None) -> bool:
    """
    Indique si le role est super admin.
    """
    return normalize_role(role) in SUPERADMIN_ROLE_KEYS
