import { isAdminRole, isAssistantRole, isSuperAdminRole, normalizeRole } from '@/lib/roles';

import type { RoleApi, UserApi } from '../types/api';

export type UsersByRole = {
  superAdmins: UserApi[];
  admins: UserApi[];
  assistants: UserApi[];
  others: UserApi[];
};

export type RolesByType = {
  defaultRoles: RoleApi[];
  assistantRoles: RoleApi[];
};

export const buildRoleLookup = (roles: RoleApi[]) => {
  return roles.reduce<Record<string, RoleApi>>((acc, role) => {
    const codeKey = normalizeRole(role.code);
    if (codeKey) {
      acc[codeKey] = role;
    }
    const nameKey = normalizeRole(role.name);
    if (nameKey && !acc[nameKey]) {
      acc[nameKey] = role;
    }
    return acc;
  }, {});
};

export const groupUsersByRole = (
  users: UserApi[],
  roleLookup: Record<string, RoleApi>,
): UsersByRole => {
  return users.reduce<UsersByRole>(
    (acc, user) => {
      const roleKey = normalizeRole(user.role);

      if (isSuperAdminRole(roleKey)) {
        acc.superAdmins.push(user);
      } else if (isAdminRole(roleKey)) {
        acc.admins.push(user);
      } else if (isAssistantRole(roleKey, roleLookup)) {
        acc.assistants.push(user);
      } else {
        acc.others.push(user);
      }

      return acc;
    },
    { superAdmins: [], admins: [], assistants: [], others: [] },
  );
};

export const countUsersByRole = (users: UserApi[], roleLookup: Record<string, RoleApi>) => {
  return users.reduce(
    (acc, user) => {
      const roleKey = normalizeRole(user.role);
      if (isAdminRole(roleKey)) {
        acc.admins += 1;
      } else if (isAssistantRole(roleKey, roleLookup)) {
        acc.assistants += 1;
      }
      return acc;
    },
    { admins: 0, assistants: 0 },
  );
};

export const splitRoles = (roles: RoleApi[]): RolesByType => {
  return roles.reduce<RolesByType>(
    (acc, role) => {
      if (role.is_system) {
        acc.defaultRoles.push(role);
      } else if (role.is_assistant) {
        acc.assistantRoles.push(role);
      }
      return acc;
    },
    { defaultRoles: [], assistantRoles: [] },
  );
};
