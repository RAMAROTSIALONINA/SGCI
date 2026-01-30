import type { UserRecord } from '../types/user-record';

export const superAdmins: UserRecord[] = [
  {
    id: 'superadmin-1',
    firstName: 'Amina',
    lastName: 'Kane',
    email: 'amina.kane@sgci.local',
  },
];

export const admins: UserRecord[] = [
  {
    id: 'admin-1',
    firstName: 'Marc',
    lastName: 'Leroy',
    email: 'marc.leroy@sgci.local',
  },
  {
    id: 'admin-2',
    firstName: 'Sarah',
    lastName: 'Diallo',
    email: 'sarah.diallo@sgci.local',
  },
];

export const assistants: UserRecord[] = [
  {
    id: 'assistant-1',
    firstName: 'Nina',
    lastName: 'Morel',
    email: 'nina.morel@sgci.local',
    canDelete: true,
  },
  {
    id: 'assistant-2',
    firstName: 'Leo',
    lastName: 'Martin',
    email: 'leo.martin@sgci.local',
    canDelete: false,
  },
  {
    id: 'assistant-3',
    firstName: 'Ines',
    lastName: 'Faye',
    email: 'ines.faye@sgci.local',
    canDelete: true,
  },
];
