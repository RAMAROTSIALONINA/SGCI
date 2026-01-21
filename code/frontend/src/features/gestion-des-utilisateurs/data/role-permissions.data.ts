import type { RolePermission } from '@/types/role-permission';

export const rolePermissions: RolePermission[] = [
  {
    id: 'users.view',
    label: 'Voir les utilisateurs',
    description: 'Consulter les comptes et profils.',
  },
  {
    id: 'users.create',
    label: 'Creer des utilisateurs',
    description: 'Ajouter de nouveaux comptes.',
  },
  {
    id: 'users.update',
    label: 'Modifier des utilisateurs',
    description: 'Mettre a jour les informations.',
  },
  {
    id: 'users.delete',
    label: 'Supprimer des utilisateurs',
    description: 'Retirer des comptes existants.',
  },
  {
    id: 'roles.manage',
    label: 'Gerer les roles',
    description: 'Creer et modifier les roles.',
  },
  {
    id: 'permissions.manage',
    label: 'Gerer les permissions',
    description: 'Adapter les droits par role.',
  },
];
