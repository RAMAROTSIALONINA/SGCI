'use client';

import * as React from 'react';

import { Badge } from '@/components/ui';
import { API_BASE_URL, fetchHealth } from '@/lib/api';

type HealthState = {
  status: 'loading' | 'ok' | 'error';
  label: string;
};

export function HealthStatus() {
  const [state, setState] = React.useState<HealthState>({
    status: 'loading',
    label: 'Checking',
  });

  React.useEffect(() => {
    const controller = new AbortController();

    const checkHealth = async () => {
      try {
        const data = await fetchHealth(controller.signal);
        const label = typeof data?.status === 'string' && data.status.trim() ? data.status : 'OK';

        setState({ status: 'ok', label });
      } catch {
        if (controller.signal.aborted) {
          return;
        }

        setState({ status: 'error', label: 'Unavailable' });
      }
    };

    checkHealth();

    return () => controller.abort();
  }, []);

  const badgeProps =
    state.status === 'ok'
      ? ({ variant: 'secondary', tone: 'success' } as const)
      : state.status === 'error'
        ? ({ variant: 'destructive' } as const)
        : ({ variant: 'muted', tone: 'info' } as const);

  return (
    <div className="flex flex-wrap items-center justify-center gap-2 text-xs text-muted-foreground">
      <span className="font-semibold uppercase tracking-[0.2em] text-foreground/70">Backend</span>
      <Badge role="status" aria-live="polite" {...badgeProps}>
        {state.label}
      </Badge>
      <span className="hidden text-[0.7rem] text-muted-foreground/80 sm:inline">
        {API_BASE_URL}
      </span>
    </div>
  );
}
