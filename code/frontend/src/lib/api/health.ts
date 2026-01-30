import { fetchJson } from './client';

export type HealthResponse = {
  status?: string;
};

export async function fetchHealth(signal?: AbortSignal) {
  return fetchJson<HealthResponse>('/health', {
    cache: 'no-store',
    signal,
  });
}
