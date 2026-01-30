"""
Couche service pour les roles.
Ici on met la logique metier avant d'appeler la base de donnees.
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.repository.permissionRepo import PermissionRepository
from app.db.repository.roleRepo import RoleRepository
from app.db.schema.user import UserOutput
from app.service.historyService import HistoryService
from app.util.roles.role_utils import is_superadmin_role, normalize_role

ROLE_SEEDS = [
    {
        "code": "super_admin",
        "name": "Super Admin",
        "description": "Acces complet + gestion utilisateurs",
        "level": 1,
        "is_system": True,
        "is_assistant": False,
    },
    {
        "code": "admin_ubs",
        "name": "Admin UBS",
        "description": "Acces complet UBS + lecture autres",
        "level": 2,
        "is_system": True,
        "is_assistant": False,
    },
    {
        "code": "admin_c2a",
        "name": "Admin C2A",
        "description": "Acces complet C2A + lecture autres",
        "level": 3,
        "is_system": True,
        "is_assistant": False,
    },
    {
        "code": "admin_site",
        "name": "Admin SITE",
        "description": "Acces complet SITE + lecture autres",
        "level": 4,
        "is_system": True,
        "is_assistant": False,
    },
    {
        "code": "admin_acr",
        "name": "Admin ACR",
        "description": "Acces complet ACR + lecture autres",
        "level": 5,
        "is_system": True,
        "is_assistant": False,
    },
    {
        "code": "assistant",
        "name": "Assistant",
        "description": "Acces restreint + 2FA obligatoire",
        "level": 6,
        "is_system": True,
        "is_assistant": True,
    },
]

FORBIDDEN_ASSISTANT_PERMISSION_CODES = {"roles.manage", "assistants.manage"}

ADMIN_PERMISSION_CODES = [
    "roles.manage",
    "assistants.manage",
]

SITE_PERMISSION_CODES = [
    "site.read",
    "site.inventaire.manage",
    "site.pertes.manage",
    "site.livraison.manage",
    "site.facturation.manage",
    "site.historique.view",
    "site.export.view",
]

C2A_PERMISSION_CODES = [
    "c2a.read",
    "c2a.dashboard.view",
    "c2a.ruptures.manage",
    "c2a.achats.manage",
    "c2a.reception.manage",
    "c2a.stocks.manage",
    "c2a.historique.view",
    "c2a.export.view",
]

UBS_PERMISSION_CODES = [
    "ubs.read",
    "ubs.validation.manage",
    "ubs.tresorerie.manage",
    "ubs.comptabilite.manage",
    "ubs.analytics.dashboard.view",
    "ubs.analytics.cashflow.view",
    "ubs.analytics.depenses.view",
    "ubs.analytics.tendances.view",
    "ubs.analytics.budget.view",
    "ubs.analytics.scheduler.view",
    "ubs.historique.view",
    "ubs.export.view",
]

ACR_PERMISSION_CODES = [
    "acr.read",
    "acr.controle.manage",
    "acr.analyse.view",
    "acr.demex.manage",
    "acr.reporting.view",
    "acr.historique.view",
    "acr.export.view",
]

TECH_PERMISSION_CODES = [
    "tech.read",
    "tech.recherche.view",
    "tech.nouveau.manage",
    "tech.consultation.view",
    "tech.import_export.manage",
]

ALL_PERMISSION_CODES = (
    ADMIN_PERMISSION_CODES
    + SITE_PERMISSION_CODES
    + C2A_PERMISSION_CODES
    + UBS_PERMISSION_CODES
    + ACR_PERMISSION_CODES
    + TECH_PERMISSION_CODES
)

PERMISSION_SEEDS = [
    {
        "code": "roles.manage",
        "name": "Gestion roles",
        "description": "Creer et modifier les roles et permissions.",
        "module": "admin",
        "is_system": True,
    },
    {
        "code": "assistants.manage",
        "name": "Gestion assistants",
        "description": "Creer ou supprimer des assistants.",
        "module": "admin",
        "is_system": True,
    },
    {
        "code": "site.read",
        "name": "SITE lecture",
        "description": "Lecture du module SITE.",
        "module": "site",
        "is_system": True,
    },
    {
        "code": "site.inventaire.manage",
        "name": "SITE inventaire",
        "description": "Gestion de l'inventaire du site.",
        "module": "site",
        "is_system": True,
    },
    {
        "code": "site.pertes.manage",
        "name": "SITE pertes",
        "description": "Gestion des pertes du site.",
        "module": "site",
        "is_system": True,
    },
    {
        "code": "site.livraison.manage",
        "name": "SITE livraison",
        "description": "Reception et suivi des livraisons.",
        "module": "site",
        "is_system": True,
    },
    {
        "code": "site.facturation.manage",
        "name": "SITE facturation",
        "description": "Gestion de la facturation du site.",
        "module": "site",
        "is_system": True,
    },
    {
        "code": "site.historique.view",
        "name": "SITE historique",
        "description": "Acces a l'historique SITE.",
        "module": "site",
        "is_system": True,
    },
    {
        "code": "site.export.view",
        "name": "SITE export",
        "description": "Export des donnees SITE.",
        "module": "site",
        "is_system": True,
    },
    {
        "code": "c2a.read",
        "name": "C2A lecture",
        "description": "Lecture du module C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "c2a.dashboard.view",
        "name": "C2A dashboard",
        "description": "Acces au tableau de bord C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "c2a.ruptures.manage",
        "name": "C2A ruptures",
        "description": "Gestion des ruptures C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "c2a.achats.manage",
        "name": "C2A achats",
        "description": "Gestion des achats C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "c2a.reception.manage",
        "name": "C2A reception",
        "description": "Reception des produits C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "c2a.stocks.manage",
        "name": "C2A stocks",
        "description": "Gestion des stocks C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "c2a.historique.view",
        "name": "C2A historique",
        "description": "Acces a l'historique C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "c2a.export.view",
        "name": "C2A export",
        "description": "Export des donnees C2A.",
        "module": "c2a",
        "is_system": True,
    },
    {
        "code": "ubs.read",
        "name": "UBS lecture",
        "description": "Lecture du module UBS.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.validation.manage",
        "name": "UBS validation",
        "description": "Validation des BILL.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.tresorerie.manage",
        "name": "UBS tresorerie",
        "description": "Gestion de la tresorerie.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.comptabilite.manage",
        "name": "UBS comptabilite",
        "description": "Comptabilite et etats financiers.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.analytics.dashboard.view",
        "name": "UBS analytics dashboard",
        "description": "Tableau de bord analytics UBS.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.analytics.cashflow.view",
        "name": "UBS analytics cashflow",
        "description": "Vue cashflow detaillee.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.analytics.depenses.view",
        "name": "UBS analytics depenses",
        "description": "Analyse des depenses.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.analytics.tendances.view",
        "name": "UBS analytics tendances",
        "description": "Analyse des tendances.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.analytics.budget.view",
        "name": "UBS analytics budget",
        "description": "Module budget.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.analytics.scheduler.view",
        "name": "UBS analytics scheduler",
        "description": "Planificateur financier.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.historique.view",
        "name": "UBS historique",
        "description": "Acces a l'historique UBS.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "ubs.export.view",
        "name": "UBS export",
        "description": "Export des donnees UBS.",
        "module": "ubs",
        "is_system": True,
    },
    {
        "code": "acr.read",
        "name": "ACR lecture",
        "description": "Lecture du module ACR.",
        "module": "acr",
        "is_system": True,
    },
    {
        "code": "acr.controle.manage",
        "name": "ACR controle",
        "description": "Controle integral ACR.",
        "module": "acr",
        "is_system": True,
    },
    {
        "code": "acr.analyse.view",
        "name": "ACR analyse",
        "description": "Analyse IA des anomalies.",
        "module": "acr",
        "is_system": True,
    },
    {
        "code": "acr.demex.manage",
        "name": "ACR demex",
        "description": "Gestion des DEMEX.",
        "module": "acr",
        "is_system": True,
    },
    {
        "code": "acr.reporting.view",
        "name": "ACR reporting",
        "description": "Reporting et audit.",
        "module": "acr",
        "is_system": True,
    },
    {
        "code": "acr.historique.view",
        "name": "ACR historique",
        "description": "Acces a l'historique ACR.",
        "module": "acr",
        "is_system": True,
    },
    {
        "code": "acr.export.view",
        "name": "ACR export",
        "description": "Export des donnees ACR.",
        "module": "acr",
        "is_system": True,
    },
    {
        "code": "tech.read",
        "name": "TECH lecture",
        "description": "Lecture du module Fiche Technique.",
        "module": "tech",
        "is_system": True,
    },
    {
        "code": "tech.recherche.view",
        "name": "TECH recherche",
        "description": "Recherche de produits.",
        "module": "tech",
        "is_system": True,
    },
    {
        "code": "tech.nouveau.manage",
        "name": "TECH creation",
        "description": "Creation de nouvelles fiches.",
        "module": "tech",
        "is_system": True,
    },
    {
        "code": "tech.consultation.view",
        "name": "TECH consultation",
        "description": "Consultation des fiches.",
        "module": "tech",
        "is_system": True,
    },
    {
        "code": "tech.import_export.manage",
        "name": "TECH import export",
        "description": "Import et export des fiches.",
        "module": "tech",
        "is_system": True,
    },
]

ROLE_PERMISSION_SEEDS = {
    "super_admin": ALL_PERMISSION_CODES,
    "admin_ubs": (
        ADMIN_PERMISSION_CODES
        + UBS_PERMISSION_CODES
        + ["site.read", "c2a.read", "acr.read", "tech.read"]
    ),
    "admin_c2a": (
        ADMIN_PERMISSION_CODES
        + C2A_PERMISSION_CODES
        + ["site.read", "ubs.read", "acr.read", "tech.read"]
    ),
    "admin_site": (
        ADMIN_PERMISSION_CODES
        + SITE_PERMISSION_CODES
        + ["c2a.read", "ubs.read", "acr.read", "tech.read"]
    ),
    "admin_acr": (
        ADMIN_PERMISSION_CODES
        + ACR_PERMISSION_CODES
        + ["site.read", "c2a.read", "ubs.read", "tech.read"]
    ),
    "assistant": [],
}


class RoleService:
    """
    Regroupe les actions liees aux roles.
    """

    def __init__(self, session: Session):
        self.__roleRepository = RoleRepository(session=session)
        self.__permissionRepository = PermissionRepository(session=session)
        self.__historyService = HistoryService(session=session)

    def list_roles(self):
        """
        Liste tous les roles en base.
        """
        return self.__roleRepository.list_roles()

    def get_role(self, role_code: str):
        """
        Recupere un role par code.
        """
        return self.__roleRepository.get_by_code_or_404(normalize_role(role_code))

    def list_permissions(self):
        """
        Liste toutes les permissions en base.
        """
        return self.__permissionRepository.list_permissions()

    def list_role_permissions(self, role_code: str):
        """
        Liste les permissions associees a un role.
        """
        role = self.__roleRepository.get_by_code_or_404(normalize_role(role_code))
        return self.__permissionRepository.list_permissions_for_role(role.id)

    def get_role_permission_codes(self, role_code: str) -> set[str]:
        """
        Recupere les codes de permissions associes a un role.
        """
        role = self.__roleRepository.get_by_code(code=normalize_role(role_code))
        if not role:
            return set()
        permissions = self.__permissionRepository.list_permissions_for_role(role.id)
        return {permission.code for permission in permissions}

    def get_assignable_permission_codes(self, user_role: str | None) -> set[str]:
        """
        Permissions que l'utilisateur courant peut assigner a un assistant.
        """
        return self._get_assignable_permission_codes(
            creator_role=user_role,
            is_assistant=True,
        )

    def create_role(
        self,
        role_data: dict,
        creator_role: str | None,
        creator_user_id: int | None,
    ):
        """
        Cree un role non systeme (role d'assistant).
        """
        code = normalize_role(role_data.get("code"))
        if not code:
            raise HTTPException(status_code=400, detail="Role code is required.")
        if not role_data.get("name"):
            raise HTTPException(status_code=400, detail="Role name is required.")
        if self.__roleRepository.exists_by_code(code):
            raise HTTPException(status_code=400, detail="Role code already exists.")

        is_assistant = bool(role_data.get("is_assistant", True))
        if not is_superadmin_role(creator_role) and not is_assistant:
            raise HTTPException(
                status_code=403,
                detail="Only super admin can create non-assistant roles.",
            )

        permission_codes = role_data.get("permission_codes") or []
        self._ensure_assignable_permissions(
            permission_codes=permission_codes,
            creator_role=creator_role,
            is_assistant=is_assistant,
        )
        permissions = self._get_permissions_by_codes(permission_codes)

        role_payload = {
            "code": code,
            "name": role_data.get("name"),
            "description": role_data.get("description"),
            "level": role_data.get("level", 6),
            "is_system": False,
            "is_assistant": is_assistant,
            "created_by_id": creator_user_id,
        }
        role = self.__roleRepository.add_role(role_payload)
        self.__roleRepository.session.flush()

        self.__permissionRepository.set_role_permissions(
            role_id=role.id,
            permission_ids=[permission.id for permission in permissions],
        )
        self.__roleRepository.session.commit()
        self.__roleRepository.session.refresh(role)
        self.__historyService.log_action(
            action="role.create",
            actor_id=creator_user_id,
            actor_role=creator_role,
            entity_type="role",
            entity_id=role.id,
            module="admin",
            description=f"Creation role {role.code}",
            meta={
                "role_code": role.code,
                "role_name": role.name,
                "is_assistant": role.is_assistant,
            },
        )
        return role

    def set_role_permissions(
        self,
        role_code: str,
        permission_codes: list[str],
        current_user: UserOutput,
    ):
        """
        Remplace les permissions d'un role existant.
        """
        role = self.__roleRepository.get_by_code_or_404(normalize_role(role_code))
        self._ensure_can_manage_role(role=role, current_user=current_user)

        self._ensure_assignable_permissions(
            permission_codes=permission_codes,
            creator_role=current_user.role,
            is_assistant=role.is_assistant,
        )
        permissions = self._get_permissions_by_codes(permission_codes)

        self.__permissionRepository.set_role_permissions(
            role_id=role.id,
            permission_ids=[permission.id for permission in permissions],
        )
        self.__roleRepository.session.commit()
        self.__historyService.log_action(
            action="role.permissions.update",
            actor_id=current_user.id,
            actor_role=current_user.role,
            entity_type="role",
            entity_id=role.id,
            module="admin",
            description=f"Mise a jour permissions role {role.code}",
            meta={
                "role_code": role.code,
                "permission_codes": permission_codes,
            },
        )
        return role

    def update_role(
        self,
        role_code: str,
        updates: dict,
        current_user: UserOutput,
    ):
        """
        Met a jour un role existant (nom, description, permissions).
        """
        role = self.__roleRepository.get_by_code_or_404(normalize_role(role_code))
        self._ensure_can_manage_role(role=role, current_user=current_user)

        updated_fields: list[str] = []
        name = updates.get("name")
        if name is not None:
            trimmed = name.strip()
            if not trimmed:
                raise HTTPException(status_code=400, detail="Role name is required.")
            role.name = trimmed
            updated_fields.append("name")

        if "description" in updates:
            description = updates.get("description")
            role.description = description if description else None
            updated_fields.append("description")

        if updates.get("permission_codes") is not None:
            permission_codes = updates.get("permission_codes") or []
            self._ensure_assignable_permissions(
                permission_codes=permission_codes,
                creator_role=current_user.role,
                is_assistant=role.is_assistant,
            )
            permissions = self._get_permissions_by_codes(permission_codes)
            self.__permissionRepository.set_role_permissions(
                role_id=role.id,
                permission_ids=[permission.id for permission in permissions],
            )
            updated_fields.append("permission_codes")

        self.__roleRepository.session.commit()
        self.__roleRepository.session.refresh(role)
        if updated_fields:
            self.__historyService.log_action(
                action="role.update",
                actor_id=current_user.id,
                actor_role=current_user.role,
                entity_type="role",
                entity_id=role.id,
                module="admin",
                description=f"Mise a jour role {role.code}",
                meta={
                    "role_code": role.code,
                    "updated_fields": updated_fields,
                    "permission_codes": updates.get("permission_codes"),
                },
            )
        return role

    def delete_role(self, role_code: str, current_user: UserOutput) -> None:
        """
        Supprime un role non systeme.
        """
        role = self.__roleRepository.get_by_code_or_404(normalize_role(role_code))
        self._ensure_can_manage_role(role=role, current_user=current_user)

        self.__permissionRepository.set_role_permissions(
            role_id=role.id, permission_ids=[]
        )
        deleted_payload = {
            "role_code": role.code,
            "role_name": role.name,
            "role_id": role.id,
        }
        self.__roleRepository.delete_role(role)
        self.__roleRepository.session.commit()
        self.__historyService.log_action(
            action="role.delete",
            actor_id=current_user.id,
            actor_role=current_user.role,
            entity_type="role",
            entity_id=deleted_payload["role_id"],
            module="admin",
            description=f"Suppression role {deleted_payload['role_code']}",
            meta=deleted_payload,
        )

    def is_assistant_role(self, role_code: str | None) -> bool:
        """
        Indique si le role est un role d'assistant.
        """
        if not role_code:
            return False
        role = self.__roleRepository.get_by_code(code=normalize_role(role_code))
        if role:
            return role.is_assistant
        return normalize_role(role_code) == "assistant"

    def seed_roles(self) -> dict:
        """
        Cree ou met a jour les roles par defaut.
        """
        existing = {role.code: role for role in self.__roleRepository.list_roles()}
        created = 0
        updated = 0

        for seed in ROLE_SEEDS:
            role = existing.get(seed["code"])
            if role is None:
                self.__roleRepository.add_role(seed)
                created += 1
                continue

            changed = False
            for field in ("name", "description", "level", "is_system", "is_assistant"):
                if getattr(role, field) != seed[field]:
                    setattr(role, field, seed[field])
                    changed = True
            if changed:
                updated += 1

        if created or updated:
            self.__roleRepository.session.commit()

        self.seed_permissions()
        self.seed_role_permissions()

        return {"created": created, "updated": updated}

    def seed_permissions(self) -> None:
        """
        Cree ou met a jour les permissions par defaut.
        """
        existing = {
            permission.code: permission
            for permission in self.__permissionRepository.list_permissions()
        }
        changed = False

        for seed in PERMISSION_SEEDS:
            permission = existing.get(seed["code"])
            if permission is None:
                self.__permissionRepository.add_permission(seed)
                changed = True
                continue

            updated = False
            for field in ("name", "description", "module", "is_system"):
                if getattr(permission, field) != seed[field]:
                    setattr(permission, field, seed[field])
                    updated = True
            if updated:
                changed = True

        if changed:
            self.__permissionRepository.session.commit()

    def seed_role_permissions(self) -> None:
        """
        Associe les permissions aux roles systemes.
        """
        roles_by_code = {role.code: role for role in self.__roleRepository.list_roles()}
        permissions_by_code = {
            permission.code: permission
            for permission in self.__permissionRepository.list_permissions()
        }

        for role_code, permission_codes in ROLE_PERMISSION_SEEDS.items():
            role = roles_by_code.get(role_code)
            if not role or not role.is_system:
                continue
            permission_ids = [
                permissions_by_code[code].id
                for code in permission_codes
                if code in permissions_by_code
            ]
            self.__permissionRepository.set_role_permissions(role.id, permission_ids)

        self.__roleRepository.session.commit()

    def _ensure_assignable_permissions(
        self,
        permission_codes: list[str],
        creator_role: str | None,
        is_assistant: bool = True,
    ) -> None:
        """
        Verifie que les permissions sont assignables par l'utilisateur courant.
        """
        assignable = self._get_assignable_permission_codes(
            creator_role=creator_role,
            is_assistant=is_assistant,
        )
        invalid = sorted(set(permission_codes) - set(assignable))
        if invalid:
            raise HTTPException(
                status_code=403,
                detail=f"Permissions not allowed: {', '.join(invalid)}",
            )

    def _get_permissions_by_codes(self, permission_codes: list[str]):
        """
        Recupere les permissions par code et verifie leur existence.
        """
        permissions = self.__permissionRepository.get_by_codes(permission_codes or [])
        found = {permission.code for permission in permissions}
        missing = sorted(set(permission_codes) - found)
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown permission codes: {', '.join(missing)}",
            )
        return permissions

    def _ensure_can_manage_role(self, role, current_user: UserOutput) -> None:
        """
        Verifie que l'utilisateur peut modifier ou supprimer un role.
        """
        if is_superadmin_role(current_user.role):
            return
        if role.is_system:
            raise HTTPException(
                status_code=403,
                detail="Only super admin can manage system roles.",
            )
        if not role.is_assistant:
            raise HTTPException(
                status_code=403,
                detail="Only super admin can manage non-assistant roles.",
            )
        if role.created_by_id != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="Only the creator admin can manage this role.",
            )

    def _get_assignable_permission_codes(
        self,
        creator_role: str | None,
        is_assistant: bool,
    ) -> set[str]:
        if is_superadmin_role(creator_role):
            assignable = set(ALL_PERMISSION_CODES)
        else:
            assignable = self.get_role_permission_codes(creator_role)
        if is_assistant:
            assignable = {
                code
                for code in assignable
                if code not in FORBIDDEN_ASSISTANT_PERMISSION_CODES
            }
        return assignable
