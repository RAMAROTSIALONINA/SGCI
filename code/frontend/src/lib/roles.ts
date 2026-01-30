export type RoleLike = {
  code: string;
  is_assistant?: boolean;
};

export const normalizeRoleCode = (role?: string) =>
  (role ?? '').trim().toLowerCase().replace(/\s+/g, '_');

export const normalizeRole = (role?: string) =>
  (role ?? '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');

export const isSuperAdminRole = (roleKey: string) =>
  roleKey === 'superadmin' || roleKey === 'super_admin';

export const isAdminRole = (roleKey: string) =>
  roleKey.startsWith('admin') || isSuperAdminRole(roleKey);

export const isAssistantRole = (
  roleKey: string,
  roleLookup?: Record<string, { is_assistant?: boolean }>,
) => roleLookup?.[roleKey]?.is_assistant ?? roleKey.includes('assistant');

export const resolveAssistantStatus = (roleCode: string, roles: RoleLike[]) =>
  roles.find((role) => role.code === roleCode)?.is_assistant;

export const formatRoleLabel = (role?: string | null) => {
  if (!role) {
    return '';
  }
  return role
    .trim()
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/\b\w/g, (match) => match.toUpperCase());
};
