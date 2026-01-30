import { fetchJson } from '@/lib/api';

import type { UserApi } from '../types/api';

type DeleteAssistantResponse = {
  message: string;
};

export async function fetchUsers(token: string, signal?: AbortSignal) {
  return fetchJson<UserApi[]>('/users', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}

export async function deleteAssistant(token: string, userId: number, signal?: AbortSignal) {
  return fetchJson<DeleteAssistantResponse>(`/users/assistants/${userId}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}
