export const IS_SERVER = typeof window === 'undefined';
export const IS_BROWSER = !IS_SERVER;

export const DEFAULT_LOCALE =
  (typeof navigator !== 'undefined' && navigator.language) || 'en-US';

export const DEFAULT_CURRENCY = 'USD';
