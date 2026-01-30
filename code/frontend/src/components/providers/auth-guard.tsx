'use client';

import { useRouter } from 'next/navigation';
import * as React from 'react';

import { refreshTokens } from '@/lib/api/client';
import { getAccessToken, getRefreshToken } from '@/lib/auth/tokens';

const LOGIN_PATH = '/';

type AuthGuardProps = {
  children: React.ReactNode;
};

export function AuthGuard({ children }: AuthGuardProps) {
  const router = useRouter();
  const [isAllowed, setIsAllowed] = React.useState(false);

  React.useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    let isMounted = true;

    const ensureAuth = async () => {
      const accessToken = getAccessToken();
      if (accessToken) {
        if (isMounted) {
          setIsAllowed(true);
        }
        return;
      }

      const refreshToken = getRefreshToken();
      if (refreshToken) {
        const refreshed = await refreshTokens();
        if (refreshed && isMounted) {
          setIsAllowed(true);
          return;
        }
      }

      if (isMounted) {
        router.replace(LOGIN_PATH);
      }
    };

    void ensureAuth();

    return () => {
      isMounted = false;
    };
  }, [router]);

  if (!isAllowed) {
    return null;
  }

  return <>{children}</>;
}
