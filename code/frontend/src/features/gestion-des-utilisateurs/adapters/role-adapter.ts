import type { PermissionApi, RoleApi, RoleWithPermissionsApi } from '../types/api';
import type { RolePermission } from '../types/role-permission';
import type { RoleRecord } from '../types/role-record';

export function mapRoleToRecord(role: RoleApi): RoleRecord {
  return {
    id: String(role.id),
    code: role.code,
    name: role.name,
    description: role.description ?? '',
    createdById: role.created_by_id ?? null,
  };
}

export function mapRolesToRecords(roles: RoleApi[]): RoleRecord[] {
  return roles.map((role) => mapRoleToRecord(role));
}

export function mapPermissionToRecord(permission: PermissionApi): RolePermission {
  return {
    id: permission.code,
    label: permission.name,
    description: permission.description ?? undefined,
  };
}

export function mapPermissionsToRecords(permissions: PermissionApi[]): RolePermission[] {
  return permissions.map((permission) => mapPermissionToRecord(permission));
}

export function mapRoleWithPermissions(role: RoleWithPermissionsApi): {
  role: RoleRecord;
  permissions: RolePermission[];
} {
  return {
    role: mapRoleToRecord(role),
    permissions: mapPermissionsToRecords(role.permissions),
  };
}
