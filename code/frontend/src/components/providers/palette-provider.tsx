'use client';

import { useTheme } from 'next-themes';
import * as React from 'react';

import { fetchCurrentUser } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';

export const PALETTE_STORAGE_KEY = 'sgci_palette';
export const DEFAULT_PALETTE = 'ocean';

export function PaletteProvider({ children }: { children: React.ReactNode }) {
  const { setTheme } = useTheme();

  React.useEffect(() => {
    if (typeof document === 'undefined') {
      return;
    }
    const stored = localStorage.getItem(PALETTE_STORAGE_KEY);
    const initialPalette = stored || DEFAULT_PALETTE;
    document.documentElement.setAttribute('data-palette', initialPalette);

    const token = getAccessToken();
    if (!token) {
      return;
    }

    const controller = new AbortController();
    fetchCurrentUser(token, controller.signal)
      .then((user) => {
        if (user.theme_mode) {
          setTheme(user.theme_mode);
        }
        if (user.palette) {
          localStorage.setItem(PALETTE_STORAGE_KEY, user.palette);
          document.documentElement.setAttribute('data-palette', user.palette);
        }
      })
      .catch(() => {
        // Ignore errors and keep local preferences.
      });

    return () => controller.abort();
  }, [setTheme]);

  return <>{children}</>;
}
