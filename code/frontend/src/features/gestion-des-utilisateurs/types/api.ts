export type UserApi = {
  id: number;
  first_name: string;
  last_name: string;
  email: string;
  role: string;
  created_by_id?: number | null;
};

export type RoleApi = {
  id: number;
  code: string;
  name: string;
  description?: string | null;
  level: number;
  is_system: boolean;
  is_assistant: boolean;
  created_by_id?: number | null;
};

export type PermissionApi = {
  id: number;
  code: string;
  name: string;
  description?: string | null;
  module?: string | null;
  is_system: boolean;
};

export type RoleWithPermissionsApi = RoleApi & {
  permissions: PermissionApi[];
};
