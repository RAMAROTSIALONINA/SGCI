import type { RoleRecord } from '@/types/role-record';

export const defaultRoles: RoleRecord[] = [
  {
    id: 'role-default-1',
    name: 'Superadmin',
    description: "Acces complet a l'application et aux parametres.",
  },
  {
    id: 'role-default-2',
    name: 'Admin',
    description: 'Gestion des utilisateurs, des roles et des permissions.',
  },
];

export const assistantRoles: RoleRecord[] = [
  {
    id: 'role-assistant-1',
    name: 'Assistant',
    description: 'Acces limite aux actions quotidiennes.',
  },
];
