import {
  type AuthTokens,
  clearAuthTokens,
  getRefreshToken,
  setAuthTokens,
} from '@/lib/auth/tokens';

const DEFAULT_API_BASE_URL = 'http://localhost:8000';

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? DEFAULT_API_BASE_URL;

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

const LOGIN_PATH = '/';
let refreshPromise: Promise<AuthTokens | null> | null = null;

const redirectToLogin = () => {
  if (typeof window === 'undefined') {
    return;
  }
  window.location.replace(LOGIN_PATH);
};

export async function refreshTokens(): Promise<AuthTokens | null> {
  if (typeof window === 'undefined') {
    return null;
  }
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return null;
  }
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = (async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!response.ok) {
        throw new ApiError(response.status, `Refresh failed with status ${response.status}`);
      }

      const data = (await response.json()) as AuthTokens;
      if (!data?.access_token || !data?.refresh_token) {
        throw new ApiError(500, 'Refresh response incomplete');
      }

      setAuthTokens(data);
      return data;
    } catch {
      clearAuthTokens();
      return null;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

export async function fetchJson<T>(
  path: string,
  init?: RequestInit,
  options?: { skipRefresh?: boolean },
): Promise<T> {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const response = await fetch(`${API_BASE_URL}${normalizedPath}`, init);

  const headers = new Headers(init?.headers ?? {});
  const hasAuthHeader = headers.has('Authorization');

  if (response.status === 401 && !options?.skipRefresh && hasAuthHeader) {
    const tokens = await refreshTokens();
    if (tokens) {
      headers.set('Authorization', `Bearer ${tokens.access_token}`);
      const retryResponse = await fetch(`${API_BASE_URL}${normalizedPath}`, {
        ...init,
        headers,
      });
      if (retryResponse.ok) {
        return (await retryResponse.json()) as T;
      }
      if (retryResponse.status === 401) {
        clearAuthTokens();
        redirectToLogin();
      }
      let retryDetail = '';
      try {
        const data = (await retryResponse.json()) as { detail?: string };
        if (data?.detail) {
          retryDetail = data.detail;
        }
      } catch {
        // Ignore parsing errors; keep fallback message.
      }
      const retryMessage = retryDetail
        ? retryDetail
        : `Request failed with status ${retryResponse.status}`;
      throw new ApiError(retryResponse.status, retryMessage);
    }
    clearAuthTokens();
    redirectToLogin();
  }

  if (!response.ok) {
    let detail = '';
    try {
      const data = (await response.json()) as { detail?: string };
      if (data?.detail) {
        detail = data.detail;
      }
    } catch {
      // Ignore parsing errors; keep fallback message.
    }
    const message = detail ? detail : `Request failed with status ${response.status}`;
    throw new ApiError(response.status, message);
  }

  return (await response.json()) as T;
}

export async function postJson<TResponse, TPayload>(
  path: string,
  payload: TPayload,
  init?: RequestInit,
): Promise<TResponse> {
  return fetchJson<TResponse>(path, {
    ...init,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
    body: JSON.stringify(payload),
  });
}
