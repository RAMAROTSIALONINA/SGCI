import { fetchJson } from './client';

export type HistoryApi = {
  id: number;
  actor_id?: number | null;
  actor_role?: string | null;
  action: string;
  entity_type?: string | null;
  entity_id?: number | null;
  module?: string | null;
  description?: string | null;
  meta?: Record<string, unknown> | null;
  created_at: string;
};

export type HistoryQuery = {
  actor_id?: number;
  action?: string;
  entity_type?: string;
  limit?: number;
  offset?: number;
};

const buildQuery = (params?: HistoryQuery) => {
  if (!params) {
    return '';
  }
  const search = new URLSearchParams();
  if (typeof params.actor_id === 'number') {
    search.set('actor_id', String(params.actor_id));
  }
  if (params.action) {
    search.set('action', params.action);
  }
  if (params.entity_type) {
    search.set('entity_type', params.entity_type);
  }
  if (typeof params.limit === 'number') {
    search.set('limit', String(params.limit));
  }
  if (typeof params.offset === 'number') {
    search.set('offset', String(params.offset));
  }
  const query = search.toString();
  return query ? `?${query}` : '';
};

export async function fetchHistory(token: string, params?: HistoryQuery, signal?: AbortSignal) {
  return fetchJson<HistoryApi[]>(`/history${buildQuery(params)}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}
