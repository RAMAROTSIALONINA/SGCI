export const ACCESS_TOKEN_KEY = 'sgci_access_token';
export const REFRESH_TOKEN_KEY = 'sgci_refresh_token';
const LEGACY_TOKEN_KEY = 'sgci_token';

export type AuthTokens = {
  access_token: string;
  refresh_token: string;
};

export function getAccessToken(): string | null {
  if (typeof window === 'undefined') {
    return null;
  }
  const token = localStorage.getItem(ACCESS_TOKEN_KEY);
  if (token) {
    return token;
  }
  const legacy = localStorage.getItem(LEGACY_TOKEN_KEY);
  if (legacy) {
    localStorage.setItem(ACCESS_TOKEN_KEY, legacy);
    return legacy;
  }
  return null;
}

export function getRefreshToken(): string | null {
  if (typeof window === 'undefined') {
    return null;
  }
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setAuthTokens(tokens: AuthTokens) {
  if (typeof window === 'undefined') {
    return;
  }
  localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access_token);
  localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
  localStorage.removeItem(LEGACY_TOKEN_KEY);
}

export function clearAuthTokens() {
  if (typeof window === 'undefined') {
    return;
  }
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(LEGACY_TOKEN_KEY);
}
