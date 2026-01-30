'use client';

import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Spinner,
} from '@/components';
import { ApiError, type CurrentUser, fetchCurrentUser } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import { formatRoleLabel } from '@/lib/roles';

export default function SettingsRolePage() {
  const [currentUser, setCurrentUser] = React.useState<CurrentUser | null>(null);
  const [status, setStatus] = React.useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = React.useState('');

  React.useEffect(() => {
    const controller = new AbortController();

    const loadUser = async () => {
      if (typeof window === 'undefined') {
        return;
      }
      const token = getAccessToken();
      if (!token) {
        setStatus('error');
        setMessage('Token manquant ou session expiree. Connectez-vous.');
        return;
      }

      try {
        const user = await fetchCurrentUser(token, controller.signal);
        setCurrentUser(user);
        setStatus('success');
      } catch (error) {
        if (controller.signal.aborted) {
          return;
        }
        setStatus('error');
        if (error instanceof ApiError) {
          setMessage(error.message);
        } else {
          setMessage("Impossible de charger vos informations d'acces.");
        }
      }
    };

    loadUser();

    return () => controller.abort();
  }, []);

  return (
    <main className="mt-8 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
      <div className="mx-auto w-full max-w-3xl">
        {status === 'loading' ? (
          <div className="flex min-h-[220px] items-center justify-center">
            <Spinner size="lg" />
          </div>
        ) : status === 'error' ? (
          <Alert variant="destructive">
            <AlertTitle>Chargement impossible</AlertTitle>
            <AlertDescription>{message}</AlertDescription>
          </Alert>
        ) : (
          <Card className="border-border/70 bg-background/70 shadow-soft">
            <CardHeader className="space-y-2">
              <CardTitle>Role et acces</CardTitle>
              <CardDescription>
                Consultez votre role et les acces principaux associes.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold text-foreground">Role actuel</span>
                <Badge variant="secondary">
                  {formatRoleLabel(currentUser?.role) || 'Non defini'}
                </Badge>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-2xl border border-border/70 bg-surface/70 p-4">
                  <p className="text-xs text-muted-foreground">Identifiant</p>
                  <p className="text-sm font-semibold text-foreground">{currentUser?.id ?? '-'}</p>
                </div>
                <div className="rounded-2xl border border-border/70 bg-surface/70 p-4">
                  <p className="text-xs text-muted-foreground">Email</p>
                  <p className="text-sm font-semibold text-foreground">
                    {currentUser?.email ?? '-'}
                  </p>
                </div>
              </div>
              <div className="rounded-2xl border border-border/70 bg-surface/70 p-4 text-sm text-muted-foreground">
                Les autorisations detaillees sont gerees par les administrateurs SGCI. Contactez le
                support si vous avez besoin d&apos;un acces supplementaire.
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </main>
  );
}
