import { fetchJson } from './client';

export type NotificationApi = {
  id: number;
  user_id: number;
  title: string;
  body?: string | null;
  category: string;
  is_read: boolean;
  read_at?: string | null;
  created_at: string;
};

export async function fetchNotifications(token: string, signal?: AbortSignal) {
  return fetchJson<NotificationApi[]>('/notifications', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}

export async function fetchNotification(
  token: string,
  notificationId: number,
  signal?: AbortSignal,
) {
  return fetchJson<NotificationApi>(`/notifications/${notificationId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}

export async function markNotificationRead(
  token: string,
  notificationId: number,
  signal?: AbortSignal,
) {
  return fetchJson<NotificationApi>(`/notifications/${notificationId}/read`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}
