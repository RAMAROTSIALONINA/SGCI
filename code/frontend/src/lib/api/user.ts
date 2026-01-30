import { fetchJson } from './client';

export type CurrentUser = {
  id: number;
  first_name: string;
  last_name: string;
  email: string;
  role: string;
  created_by_id?: number | null;
  theme_mode?: string | null;
  palette?: string | null;
};

type CurrentUserResponse = {
  data: CurrentUser;
};

export async function fetchCurrentUser(token: string, signal?: AbortSignal) {
  const response = await fetchJson<CurrentUserResponse>('/protected', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });

  return response.data;
}

export type UpdateCurrentUserPayload = {
  first_name?: string;
  last_name?: string;
  email?: string;
  current_password?: string;
  password?: string;
  theme_mode?: string;
  palette?: string;
};

export async function updateCurrentUser(
  token: string,
  payload: UpdateCurrentUserPayload,
  signal?: AbortSignal,
) {
  return fetchJson<CurrentUser>('/users/me', {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
    signal,
  });
}
