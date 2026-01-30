import { fetchJson, postJson } from '@/lib/api';

import type { PermissionApi, RoleApi, RoleWithPermissionsApi } from '../types/api';

export async function fetchRoles(token?: string, signal?: AbortSignal) {
  return fetchJson<RoleApi[]>('/roles', {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    signal,
  });
}

export async function fetchAssignablePermissions(token: string, signal?: AbortSignal) {
  return fetchJson<PermissionApi[]>('/roles/assignable-permissions', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}

export async function fetchRolePermissions(token: string, roleCode: string, signal?: AbortSignal) {
  return fetchJson<PermissionApi[]>(`/roles/${encodeURIComponent(roleCode)}/permissions`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}

export type UpdateRolePayload = {
  name?: string;
  description?: string;
  permission_codes?: string[];
};

export async function updateRole(
  token: string,
  roleCode: string,
  payload: UpdateRolePayload,
  signal?: AbortSignal,
) {
  return fetchJson<RoleWithPermissionsApi>(`/roles/${encodeURIComponent(roleCode)}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
    signal,
  });
}

type DeleteRoleResponse = {
  message: string;
};

export async function deleteRole(token: string, roleCode: string, signal?: AbortSignal) {
  return fetchJson<DeleteRoleResponse>(`/roles/${encodeURIComponent(roleCode)}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}

export type CreateRolePayload = {
  code: string;
  name: string;
  description?: string;
  permission_codes: string[];
  is_assistant?: boolean;
  level?: number;
};

export async function createRole(token: string, payload: CreateRolePayload, signal?: AbortSignal) {
  return postJson<RoleWithPermissionsApi, CreateRolePayload>('/roles', payload, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}
