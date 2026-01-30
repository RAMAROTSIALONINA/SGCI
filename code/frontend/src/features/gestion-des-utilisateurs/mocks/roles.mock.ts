import type { RoleRecord } from '../types/role-record';

export const defaultRoles: RoleRecord[] = [
  {
    id: 'role-default-1',
    code: 'superadmin',
    name: 'Superadmin',
    description: "Acces complet a l'application et aux parametres.",
    createdById: null,
  },
  {
    id: 'role-default-2',
    code: 'admin',
    name: 'Admin',
    description: 'Gestion des utilisateurs, des roles et des permissions.',
    createdById: null,
  },
];

export const assistantRoles: RoleRecord[] = [
  {
    id: 'role-assistant-1',
    code: 'assistant',
    name: 'Assistant',
    description: 'Acces limite aux actions quotidiennes.',
    createdById: null,
  },
];
