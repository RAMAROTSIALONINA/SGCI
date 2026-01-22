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

import anyio
import secrets

from app.db.repository.twofaRepo import TwoFARepository

from datetime import datetime, timezone, timedelta
from app.service.emailService import send_otp_email
from app.service.roleService import RoleService

ASSISTANT_ROLE = "assistant"
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
DEFAULT_SEED_PASSWORD = "Admin123!"
DEFAULT_USER_SEEDS = [
    {
        "first_name": "Amina",
        "last_name": "Kane",
        "email": "lionsclaudius17@gmail.com",
        "role": "super_admin",
    },
    {
        "first_name": "Marc",
        "last_name": "Leroy",
        "email": "admin.ubs@sgci.com",
        "role": "admin_ubs",
    },
    {
        "first_name": "Sarah",
        "last_name": "Diallo",
        "email": "admin.c2a@sgci.com",
        "role": "admin_c2a",
    },
    {
        "first_name": "Louis",
        "last_name": "Ndiaye",
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

OPT_TTL_MiNUTES = 5
MAX_OPT_ATTEMPTS = 5


def normalize_role(role: str | None) -> str:
    """
    Normalise un role pour la comparaison (minuscule, espaces -> underscore).
    """
    if not role:
        return ""
    return role.strip().lower().replace(" ", "_")


def generate_opt_6_digits() -> str:
    """
    Genere un code OTP a 6 chiffres.
    """
    return f"{secrets.randbelow(1000000):06}"


class UserService:
    """
    Regroupe les actions liees aux utilisateurs.
    Ce service utilise un repository pour lire et ecrire dans la base.
    """

    def __init__(self, session: Session):
        self.__userRepository = UserRepository(session=session)

    def signup(self, user_details: UserInCreate, current_user: UserOutput) -> dict:
        """
        Inscription d'un nouvel utilisateur.
        Verifie que l'email n'existe pas deja, transforme le mot de passe
        en hash (une version non lisible), puis enregistre l'utilisateur.
        """
        # verifie si l'email existe deja
        if self.__userRepository.user_exist_by_email(email=user_details.email):
            raise HTTPException(
                status_code=400, detail="User with this email already exists."
            )
        hashed_password = HashHelper.get_password_hash(
            plain_password=user_details.password
        )
        #hash le mot de passe
        user_details.password = hashed_password

        role_service = RoleService(session=self.__userRepository.session)
        role_code = normalize_role(user_details.role_code) if user_details.role_code else ASSISTANT_ROLE

        role = role_service.get_role(role_code)
        if not role_service.is_assistant_role(role_code):
            raise HTTPException(
                status_code=400,
                detail="Role is not an assistant role.",
            )

        assignable = role_service.get_assignable_permission_codes(current_user.role)
        role_permissions = role_service.get_role_permission_codes(role_code)
        forbidden = sorted(set(role_permissions) - set(assignable))
        if forbidden:
            raise HTTPException(
                status_code=403,
                detail="Role permissions exceed creator permissions.",
            )

        # cree l'utilisateur en base
        user = self.__userRepository.create_user(
            user_data=user_details,
            role=role.code,
            isActive=False,
            isVerified=False,
            created_by_id=current_user.id,
        )

        return {"message": "Assistant cree."}
    
    def verify_otp(self, email: str, code: str) -> UserWithToken:
        """
        Verification du code OTP 2FA.
        Verifie que le code est correct et non expire.
        Si oui, marque l'utilisateur comme verifie et actif.
        """
        # recupere l'utilisateur
        user = self.__userRepository.get_user_by_email(email=email)
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )
        
        # recupere le dernier code 2FA valide
        repo_2fa = TwoFARepository(session=self.__userRepository.session)
        code_row = repo_2fa.get_latest_valid_code(user_id=user.id)

        # verifie le code
        if not code_row:
            raise HTTPException(
                status_code=400,
                detail="No valid code found. Please request a new one."
            )
        
        # verifie le nombre de tentatives
        if code_row.attempts >= MAX_OPT_ATTEMPTS:
            raise HTTPException(
                status_code=400,
                detail="Maximum attempts exceeded. Please request a new code."
            )
        
        # verifie la validite du code
        if not HashHelper.verify_password(
            plain_password=code,
            hashed_password=code_row.code_hash
        ):
            repo_2fa.add_attempt(code=code_row)
            raise HTTPException(
                status_code=400,
                detail="Invalid code. Please try again."
            )
        
        # marque le code comme utilise
        repo_2fa.mark_used(code=code_row)

        # marque l'utilisateur comme verifie et actif
        user.is_verified = True
        user.is_active = True
        self.__userRepository.session.commit()
        self.__userRepository.session.refresh(user)
        token = AuthHandler.sign_jwt(user_id=user.id)
        if not token:
            raise HTTPException(
                status_code=500,
                detail="Unable to process request"
            )
        return UserWithToken(token=token)

    def login(self, login_details: UserInLogin) -> UserWithToken | dict:
        """
        Connexion d'un utilisateur.
        Verifie l'email, compare le mot de passe, puis genere un token
        (ou declenche un OTP pour un assistant).
        """
        user = self.__userRepository.get_user_by_email(email=login_details.email)
        if not user:
            raise HTTPException(
                status_code=404,
                detail="Please, create an account."
            )

        if not HashHelper.verify_password(
            plain_password=login_details.password,
            hashed_password=user.password
        ):
            raise HTTPException(status_code=400, detail="Invalid credentials.")

        role_key = normalize_role(user.role)
        if RoleService(session=self.__userRepository.session).is_assistant_role(role_key):
            creator = None
            if user.created_by_id:
                creator = self.__userRepository.get_user_by_id(user.created_by_id)
            creator_role = normalize_role(creator.role) if creator else ""
            if creator and creator.email and creator_role in ADMIN_ROLE_KEYS:
                opt = generate_opt_6_digits()
                opt_hash = HashHelper.get_password_hash(opt)
                expired_at = datetime.now(timezone.utc) + timedelta(minutes=OPT_TTL_MiNUTES)

                TwoFARepository(session=self.__userRepository.session).create_code(
                    user_id=user.id,
                    code_hash=opt_hash,
                    expires_at=expired_at
                )

                try:
                    anyio.run(send_otp_email, creator.email, opt)
                except Exception:
                    raise HTTPException(
                        status_code=500,
                        detail="Unable to send verification email."
                    )

                return {"message": "Code envoye au createur."}

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="User account is inactive."
            )
        if not user.is_verified:
            raise HTTPException(
                status_code=403,
                detail="User account is not verified."
            )

        token = AuthHandler.sign_jwt(user_id=user.id)
        if token:
            return UserWithToken(token=token)
        raise HTTPException(
            status_code=500,
            detail="Unable to process request"
        )

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

    def list_users(self) -> list[UserOutput]:
        """
        Liste tous les utilisateurs en base.
        """
        users = self.__userRepository.list_users()
        return [
            UserOutput(
                id=user.id,
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                role=user.role,
            )
            for user in users
        ]

    def delete_assistant(self, user_id: int, current_user: UserOutput) -> dict:
        """
        Supprime un assistant par son identifiant.
        """
        user = self.__userRepository.get_user_by_id(user_id=user_id)
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )
        role_key = (user.role or "").strip().lower().replace(" ", "_")
        if not RoleService(session=self.__userRepository.session).is_assistant_role(role_key):
            raise HTTPException(
                status_code=403,
                detail="Only assistant accounts can be deleted with this endpoint."
            )
        current_role = (current_user.role or "").strip().lower().replace(" ", "_")
        if current_role not in SUPERADMIN_ROLE_KEYS:
            if user.created_by_id != current_user.id:
                raise HTTPException(
                    status_code=403,
                    detail="Only the creator admin can delete this assistant."
                )
        self.__userRepository.delete_user(user)
        return {"message": "Assistant deleted."}

    def seed_default_users(self) -> dict:
        """
        Cree les utilisateurs par defaut (hors assistants) pour les tests.
        """
        created = 0
        skipped = 0

        for seed in DEFAULT_USER_SEEDS:
            if self.__userRepository.user_exist_by_email(email=seed["email"]):
                skipped += 1
                continue

            user_details = UserInCreate(
                first_name=seed["first_name"],
                last_name=seed["last_name"],
                email=seed["email"],
                password=DEFAULT_SEED_PASSWORD,
            )
            user_details.password = HashHelper.get_password_hash(
                plain_password=user_details.password
            )
            self.__userRepository.create_user(
                user_data=user_details,
                role=seed["role"],
                isActive=True,
                isVerified=True,
            )
            created += 1

        return {"created": created, "skipped": skipped}
