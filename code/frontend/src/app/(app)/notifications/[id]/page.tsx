'use client';

import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  buttonVariants,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  PageHeader,
  Spinner,
} from '@/components';
import { cn } from '@/components/utils';
import { ApiError, fetchNotification, markNotificationRead, type NotificationApi } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import { formatDateTimeShort } from '@/lib/formatters';

const extractOtpCode = (body?: string | null) => {
  if (!body) {
    return null;
  }
  const match = body.match(/code(?:\s+de\s+verification)?(?:\s+2fa)?\s*(?:est|:)?\s*([0-9]{6})/i);
  return match?.[1] ?? null;
};

export default function NotificationDetailPage() {
  const params = useParams();
  const notificationId = Number(params?.id);
  const [notification, setNotification] = React.useState<NotificationApi | null>(null);
  const [status, setStatus] = React.useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = React.useState('');

  React.useEffect(() => {
    const controller = new AbortController();

    const loadNotification = async () => {
      if (typeof window === 'undefined') {
        return;
      }
      if (!Number.isFinite(notificationId)) {
        setStatus('error');
        setError('Identifiant de notification invalide.');
        return;
      }
      const token = getAccessToken();
      if (!token) {
        setStatus('error');
        setError('Token manquant ou session expiree. Connectez-vous.');
        return;
      }
      try {
        const response = await fetchNotification(token, notificationId, controller.signal);
        setNotification(response);
        if (!response.is_read) {
          try {
            const updated = await markNotificationRead(token, notificationId, controller.signal);
            setNotification(updated);
            if (typeof window !== 'undefined') {
              window.dispatchEvent(new Event('sgci-notifications-updated'));
            }
          } catch {
            // Ignore marking errors; detail page should still render.
          }
        }
        setStatus('success');
      } catch (fetchError) {
        if (controller.signal.aborted) {
          return;
        }
        setStatus('error');
        if (fetchError instanceof ApiError) {
          if (fetchError.status === 401) {
            setError('Session invalide ou expiree. Reconnectez-vous.');
          } else if (fetchError.status === 404) {
            setError('Notification introuvable.');
          } else if (fetchError.status === 403) {
            setError('Acces refuse. Verifiez vos droits.');
          } else {
            setError(fetchError.message);
          }
        } else {
          setError('Impossible de charger la notification.');
        }
      }
    };

    loadNotification();
    return () => controller.abort();
  }, [notificationId]);

  const createdLabel = formatDateTimeShort(notification?.created_at);
  const readLabel = formatDateTimeShort(notification?.read_at);
  const otpCode = extractOtpCode(notification?.body);

  return (
    <>
      <PageHeader title="Notification" description="Details complets du message selectionne." />

      <main className="mt-8 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
        {status === 'loading' ? (
          <div className="flex min-h-[240px] items-center justify-center">
            <Spinner size="lg" />
          </div>
        ) : status === 'error' ? (
          <Alert variant="destructive">
            <AlertTitle>Chargement impossible</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : notification ? (
          <div className="space-y-6">
            <Link
              href="/notifications"
              className={cn(
                buttonVariants({ variant: 'ghost', size: 'icon' }),
                'h-9 w-9 rounded-full border border-border/70 bg-surface/70 hover:bg-surface-muted/80 active:bg-surface/70',
              )}
              aria-label="Retour aux notifications"
            >
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              <span className="sr-only">Retour aux notifications</span>
            </Link>
            <Card className="border-border/70 border-l-4 border-l-primary/80 bg-card/90 shadow-soft-lg">
              <CardHeader className="space-y-3">
                <div className="flex flex-wrap items-center gap-3">
                  <Badge
                    variant={notification.is_read ? 'muted' : 'secondary'}
                    className={
                      notification.is_read
                        ? '!border-[color:rgb(var(--palette-primary-rgb)_/_0.6)] !text-[color:rgb(var(--palette-primary-rgb)_/_0.85)] dark:!border-[color:rgb(var(--palette-primary-rgb)_/_0.7)] dark:!text-[color:rgb(var(--palette-primary-rgb)_/_0.92)]'
                        : '!border-[color:rgb(var(--palette-secondary-rgb)_/_0.6)] !text-[color:rgb(var(--palette-secondary-rgb)_/_0.85)] dark:!border-[color:rgb(var(--palette-secondary-rgb)_/_0.7)] dark:!text-[color:rgb(var(--palette-secondary-rgb)_/_0.92)]'
                    }
                  >
                    {notification.is_read ? 'Lu' : 'Non lu'}
                  </Badge>
                  {notification.category ? (
                    <Badge variant="outline">{notification.category}</Badge>
                  ) : null}
                </div>
                <CardTitle className="text-2xl">{notification.title}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm text-foreground/90">
                {notification.body ? (
                  <p className="text-base text-foreground">{notification.body}</p>
                ) : (
                  <p className="text-muted-foreground">
                    Aucun detail disponible pour cette notification.
                  </p>
                )}
                {otpCode ? (
                  <div className="rounded-2xl border border-border/70 bg-surface-muted p-4">
                    <div className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                      Code 2FA
                    </div>
                    <div className="mt-2 text-3xl font-semibold tracking-[0.3em] text-foreground">
                      {otpCode}
                    </div>
                  </div>
                ) : null}
                <div className="grid gap-2 text-xs text-muted-foreground">
                  {createdLabel ? <div>Envoyee le: {createdLabel}</div> : null}
                  {readLabel ? <div>Lue le: {readLabel}</div> : null}
                </div>
              </CardContent>
            </Card>
          </div>
        ) : null}
      </main>
    </>
  );
}
