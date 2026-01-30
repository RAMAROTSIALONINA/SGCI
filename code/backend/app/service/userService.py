"""
Couche service pour les utilisateurs.
Ici on met la logique metier (les etapes) avant d'appeler la base de donnees.
"""

from datetime import datetime, timedelta, timezone

import anyio
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.security.authHandler import AuthHandler
from app.core.security.hashHelper import HashHelper
from app.db.repository.notificationRepo import NotificationRepository
from app.db.repository.twofaRepo import TwoFARepository
from app.db.repository.userPreferenceRepo import UserPreferenceRepository
from app.db.repository.userRepo import UserRepository
from app.db.schema.user import (
    UserInCreate,
    UserInLogin,
    UserInUpdate,
    UserOutput,
    UserWithToken,
)
from app.service.emailService import send_otp_email
from app.service.historyService import HistoryService
from app.service.roleService import RoleService
from app.util.roles.role_utils import ADMIN_ROLE_KEYS, SUPERADMIN_ROLE_KEYS, normalize_role
from app.util.users.helpers import (
    ASSISTANT_ROLE,
    DEFAULT_SEED_PASSWORD,
    DEFAULT_USER_SEEDS,
    MAX_OTP_ATTEMPTS,
    OTP_TTL_MINUTES,
    generate_otp_6_digits,
)


class UserService:
    """
    Regroupe les actions liees aux utilisateurs.
    Ce service utilise un repository pour lire et ecrire dans la base.
    """

    def __init__(self, session: Session):
        self.__userRepository = UserRepository(session=session)
        self.__preferenceRepository = UserPreferenceRepository(session=session)
        self.__roleService = RoleService(session=session)
        self.__twofaRepository = TwoFARepository(session=session)
        self.__notificationRepository = NotificationRepository(session=session)
        self.__historyService = HistoryService(session=session)

    def _is_superadmin(self, role: str | None) -> bool:
        return normalize_role(role) in SUPERADMIN_ROLE_KEYS

    def _is_assistant(self, role: str | None) -> bool:
        return self.__roleService.is_assistant_role(normalize_role(role))

    def _get_admin_creator(self, user):
        if not user.created_by_id:
            return None
        creator = self.__userRepository.get_by_id(user.created_by_id)
        if not creator or not creator.email:
            return None
        if normalize_role(creator.role) not in ADMIN_ROLE_KEYS:
            return None
        return creator

    def _issue_tokens(self, user_id: int) -> UserWithToken:
        access_token = AuthHandler.sign_access_jwt(user_id=user_id)
        refresh_token = AuthHandler.sign_refresh_jwt(user_id=user_id)
        if not access_token or not refresh_token:
            raise HTTPException(
                status_code=500,
                detail="Unable to process request",
            )
        return UserWithToken(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def refresh_tokens(self, user_id: int) -> UserWithToken:
        user = self.__userRepository.get_by_id_or_404(user_id)
        return self._issue_tokens(user_id=user.id)

    def signup(self, user_details: UserInCreate, current_user: UserOutput) -> dict:
        """
        Inscription d'un nouvel utilisateur.
        Verifie que l'email n'existe pas deja, transforme le mot de passe
        en hash (une version non lisible), puis enregistre l'utilisateur.
        """
        # verifie si l'email existe deja
        if self.__userRepository.exists_by_email(email=user_details.email):
            raise HTTPException(
                status_code=400, detail="User with this email already exists."
            )
        hashed_password = HashHelper.get_password_hash(
            plain_password=user_details.password
        )
        # hash le mot de passe
        user_details.password = hashed_password

        role_code = (
            normalize_role(user_details.role_code)
            if user_details.role_code
            else ASSISTANT_ROLE
        )

        role = self.__roleService.get_role(role_code)
        is_assistant_role = self.__roleService.is_assistant_role(role_code)
        is_superadmin = self._is_superadmin(current_user.role)
        if not is_assistant_role and not is_superadmin:
            raise HTTPException(
                status_code=403,
                detail="Only super admin can create non-assistant roles.",
            )
        if not is_superadmin:
            if role.created_by_id != current_user.id:
                raise HTTPException(
                    status_code=403,
                    detail="Only the role creator can assign this role.",
                )

        if not is_superadmin:
            assignable = self.__roleService.get_assignable_permission_codes(
                current_user.role
            )
            role_permissions = self.__roleService.get_role_permission_codes(role_code)
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
            is_active=not is_assistant_role,
            is_verified=not is_assistant_role,
            created_by_id=current_user.id,
        )

        self.__historyService.log_action(
            action="user.create",
            actor_id=current_user.id,
            actor_role=current_user.role,
            entity_type="user",
            entity_id=user.id,
            module="admin",
            description=f"Creation utilisateur {user.email}",
            meta={
                "email": user.email,
                "role": user.role,
                "created_user_id": user.id,
            },
        )

        if is_assistant_role:
            return {"message": "Assistant cree."}
        return {"message": "Admin cree."}

    def _send_assistant_otp(self, user) -> None:
        """
        Genere un OTP et envoie le code a l'assistant par email.
        """
        otp_code = generate_otp_6_digits()
        otp_hash = HashHelper.get_password_hash(otp_code)
        expired_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_TTL_MINUTES)

        self.__twofaRepository.create_code(
            user_id=user.id, code_hash=otp_hash, expires_at=expired_at
        )

        try:
            anyio.run(send_otp_email, user.email, otp_code)
        except Exception:
            raise HTTPException(
                status_code=500, detail="Unable to send verification email."
            )

    def verify_otp(self, email: str, code: str) -> UserWithToken:
        """
        Verification du code OTP 2FA.
        Verifie que le code est correct et non expire.
        Si oui, marque l'utilisateur comme verifie et actif.
        """
        # recupere l'utilisateur
        user = self.__userRepository.get_by_email_or_404(email)

        # recupere le dernier code 2FA valide
        code_row = self.__twofaRepository.get_latest_valid_code(user_id=user.id)

        # verifie le code
        if not code_row:
            raise HTTPException(
                status_code=400, detail="No valid code found. Please request a new one."
            )

        # verifie le nombre de tentatives
        if code_row.attempts >= MAX_OTP_ATTEMPTS:
            raise HTTPException(
                status_code=400,
                detail="Maximum attempts exceeded. Please request a new code.",
            )

        # verifie la validite du code
        if not HashHelper.verify_password(
            plain_password=code, hashed_password=code_row.code_hash
        ):
            self.__twofaRepository.add_attempt(code=code_row)
            raise HTTPException(
                status_code=400, detail="Invalid code. Please try again."
            )

        # marque le code comme utilise
        self.__twofaRepository.mark_used(code=code_row)

        # marque l'utilisateur comme verifie et actif
        user.is_verified = True
        user.is_active = True
        self.__userRepository.session.commit()
        self.__userRepository.session.refresh(user)

        if self._is_assistant(user.role):
            creator = self._get_admin_creator(user)
            if creator:
                self.__notificationRepository.create_notification(
                    user_id=creator.id,
                    title="Assistant connecte",
                    body=(
                        f"{user.first_name} {user.last_name} "
                        f"({user.email}) s'est connecte."
                    ),
                    category="security",
                )
        return self._issue_tokens(user_id=user.id)

    def login(self, login_details: UserInLogin) -> UserWithToken | dict:
        """
        Connexion d'un utilisateur.
        Verifie l'email, compare le mot de passe, puis genere un token
        (ou declenche un OTP pour un assistant).
        """
        user = self.__userRepository.get_by_email_or_404(
            login_details.email,
            detail="Please, create an account.",
        )

        if not HashHelper.verify_password(
            plain_password=login_details.password, hashed_password=user.password
        ):
            raise HTTPException(status_code=400, detail="Invalid credentials.")

        if self._is_assistant(user.role):
            creator = self._get_admin_creator(user)
            if creator:
                self._send_assistant_otp(user)
                return {"message": "Code envoye a l'assistant."}

        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is inactive.")
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="User account is not verified.")

        return self._issue_tokens(user_id=user.id)

    def resend_otp(self, email: str) -> dict:
        """
        Renvoie un code OTP pour un assistant.
        """
        user = self.__userRepository.get_by_email_or_404(email)

        if not self._is_assistant(user.role):
            raise HTTPException(
                status_code=400, detail="OTP is only available for assistants."
            )

        creator = self._get_admin_creator(user)
        if not creator:
            raise HTTPException(
                status_code=400, detail="No admin creator found for this assistant."
            )

        self._send_assistant_otp(user)
        return {"message": "Code renvoye a l'assistant."}

    def get_by_id(self, user_id: int) -> UserOutput:
        """
        Recupere un utilisateur avec son identifiant.
        Si aucun utilisateur n'est trouve, une erreur est levee.
        """
        user = self.__userRepository.get_by_id_or_404(user_id)
        preference = self.__preferenceRepository.get_by_user_id(user.id)
        return UserOutput(
            id=user.id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=user.role,
            created_by_id=user.created_by_id,
            theme_mode=preference.theme_mode if preference else None,
            palette=preference.palette if preference else None,
        )

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
                created_by_id=user.created_by_id,
            )
            for user in users
        ]

    def delete_assistant(self, user_id: int, current_user: UserOutput) -> dict:
        """
        Supprime un assistant par son identifiant.
        """
        user = self.__userRepository.get_by_id_or_404(user_id)
        if not self._is_assistant(user.role):
            raise HTTPException(
                status_code=403,
                detail="Only assistant accounts can be deleted with this endpoint.",
            )
        if not self._is_superadmin(current_user.role):
            if user.created_by_id != current_user.id:
                raise HTTPException(
                    status_code=403,
                    detail="Only the creator admin can delete this assistant.",
                )
        deleted_payload = {
            "email": user.email,
            "role": user.role,
            "deleted_user_id": user.id,
        }
        self.__userRepository.delete_user(user)
        self.__historyService.log_action(
            action="assistant.delete",
            actor_id=current_user.id,
            actor_role=current_user.role,
            entity_type="user",
            entity_id=deleted_payload["deleted_user_id"],
            module="admin",
            description=f"Suppression assistant {deleted_payload['email']}",
            meta=deleted_payload,
        )
        return {"message": "Assistant deleted."}

    def seed_default_users(self) -> dict:
        """
        Cree les utilisateurs par defaut (hors assistants) pour les tests.
        """
        created = 0
        skipped = 0

        for seed in DEFAULT_USER_SEEDS:
            if self.__userRepository.exists_by_email(email=seed["email"]):
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
                is_active=True,
                is_verified=True,
            )
            created += 1

        return {"created": created, "skipped": skipped}

    def update_current_user(
        self,
        user_details: UserInUpdate,
        current_user: UserOutput,
    ) -> UserOutput:
        """
        Met a jour le profil de l'utilisateur courant.
        """
        user = self.__userRepository.get_by_id_or_404(current_user.id)

        changed_fields: list[str] = []
        updates: dict[str, object] = {}
        if user_details.first_name is not None:
            updates["first_name"] = user_details.first_name
            changed_fields.append("first_name")
        if user_details.last_name is not None:
            updates["last_name"] = user_details.last_name
            changed_fields.append("last_name")
        if user_details.email is not None:
            new_email = user_details.email
            if new_email != user.email and self.__userRepository.exists_by_email(
                email=new_email
            ):
                raise HTTPException(
                    status_code=400, detail="User with this email already exists."
                )
            updates["email"] = new_email
            changed_fields.append("email")
        if user_details.password is not None:
            if not user_details.current_password:
                raise HTTPException(
                    status_code=400,
                    detail="Current password is required.",
                )
            if not HashHelper.verify_password(
                plain_password=user_details.current_password,
                hashed_password=user.password,
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Current password is incorrect.",
                )
            updates["password"] = HashHelper.get_password_hash(
                plain_password=user_details.password
            )
            changed_fields.append("password")

        if user_details.theme_mode is not None or user_details.palette is not None:
            self.__preferenceRepository.upsert_preferences(
                user_id=user.id,
                theme_mode=user_details.theme_mode,
                palette=user_details.palette,
            )
            if user_details.theme_mode is not None:
                changed_fields.append("theme_mode")
            if user_details.palette is not None:
                changed_fields.append("palette")

        updated = user
        if updates:
            updated = self.__userRepository.update_user(user=user, updates=updates)

        preference = self.__preferenceRepository.get_by_user_id(user.id)
        if changed_fields:
            self.__historyService.log_action(
                action="user.update",
                actor_id=updated.id,
                actor_role=updated.role,
                entity_type="user",
                entity_id=updated.id,
                module="admin",
                description=f"Mise a jour utilisateur ({', '.join(changed_fields)})",
                meta={"fields": changed_fields},
            )
        return UserOutput(
            id=updated.id,
            first_name=updated.first_name,
            last_name=updated.last_name,
            email=updated.email,
            role=updated.role,
            created_by_id=updated.created_by_id,
            theme_mode=preference.theme_mode if preference else None,
            palette=preference.palette if preference else None,
        )
