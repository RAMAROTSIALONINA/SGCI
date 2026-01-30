'use client';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
  CardHeader,
  CardTitle,
  PageHeader,
  Spinner,
} from '@/components';
import { cn } from '@/components/utils';
import { ApiError, fetchNotifications, type NotificationApi } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import { formatDateTimeShort } from '@/lib/formatters';
export default function NotificationsPage() {
  const [notifications, setNotifications] = React.useState<NotificationApi[]>([]);
  const [status, setStatus] = React.useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = React.useState('');
  const [filter, setFilter] = React.useState<'all' | 'unread' | 'read'>('all');
  const unreadCount = React.useMemo(
    () => notifications.filter((item) => !item.is_read).length,
    [notifications],
  );
  const readCount = React.useMemo(
    () => notifications.filter((item) => item.is_read).length,
    [notifications],
  );
  const filteredNotifications = React.useMemo(() => {
    if (filter === 'unread') {
      return notifications.filter((item) => !item.is_read);
    }
    if (filter === 'read') {
      return notifications.filter((item) => item.is_read);
    }
    return notifications;
  }, [filter, notifications]);
  React.useEffect(() => {
    const controller = new AbortController();
    const pollIntervalMs = 30_000;
    const loadNotifications = async ({ silent = false } = {}) => {
      if (typeof window === 'undefined') {
        return;
      }
      const token = getAccessToken();
      if (!token) {
        if (!silent) {
          setStatus('error');
          setError('Token manquant ou session expiree. Connectez-vous.');
        }
        return;
      }
      try {
        const response = await fetchNotifications(token, controller.signal);
        setNotifications(response);
        setStatus('success');
      } catch (fetchError) {
        if (controller.signal.aborted) {
          return;
        }
        if (!silent) {
          setStatus('error');
          if (fetchError instanceof ApiError) {
            if (fetchError.status === 401) {
              setError('Session invalide ou expiree. Reconnectez-vous.');
            } else if (fetchError.status === 403) {
              setError('Acces refuse. Verifiez vos droits.');
            } else {
              setError(fetchError.message);
            }
          } else {
            setError('Impossible de charger les notifications.');
          }
        }
      }
    };
    loadNotifications();
    const pollId = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        loadNotifications({ silent: true });
      }
    }, pollIntervalMs);
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        loadNotifications({ silent: true });
      }
    };
    const handleNotificationsUpdated = () => {
      loadNotifications({ silent: true });
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleVisibilityChange);
    window.addEventListener('sgci-notifications-updated', handleNotificationsUpdated);
    return () => {
      window.clearInterval(pollId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleVisibilityChange);
      window.removeEventListener('sgci-notifications-updated', handleNotificationsUpdated);
      controller.abort();
    };
  }, []);
  return (
    <>
      <PageHeader
        title="Notifications"
        description="Consultez les alertes et mises a jour importantes."
      />
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
        ) : notifications.length === 0 ? (
          <Alert>
            <AlertTitle>Aucune notification</AlertTitle>
            <AlertDescription>Aucun message n&apos;est disponible pour le moment.</AlertDescription>
          </Alert>
        ) : (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-border/60 bg-surface-muted/70 px-5 py-4">
              <div>
                <p className="text-sm font-semibold text-foreground">Toutes les notifications</p>
                <p className="text-xs text-muted-foreground">
                  {notifications.length} total, {unreadCount} non lue
                  {unreadCount > 1 ? 's' : ''}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 rounded-full border border-border/60 bg-surface px-2 py-2 shadow-soft">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className={cn(
                  'rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em]',
                  filter === 'all'
                    ? 'border-primary/40 bg-primary/10 text-foreground shadow-soft hover:border-primary/40 hover:bg-primary/10 hover:text-foreground active:bg-primary/10'
                    : 'border-border/70 bg-background text-foreground hover:border-border/70 hover:bg-background hover:text-foreground active:bg-background',
                )}
                aria-pressed={filter === 'all'}
                onClick={() => setFilter('all')}
              >
                Toutes
                <span
                  className={cn(
                    'rounded-full px-2 py-0.5 text-[10px] font-semibold',
                    filter === 'all'
                      ? 'bg-primary/15 text-foreground'
                      : 'bg-primary/10 text-primary/80',
                  )}
                >
                  {notifications.length}
                </span>
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className={cn(
                  'rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em]',
                  filter === 'unread'
                    ? 'border-amber-400/60 bg-amber-100 text-foreground shadow-soft hover:border-amber-400/60 hover:bg-amber-100 hover:text-foreground dark:border-amber-500/40 dark:bg-amber-500/20 dark:text-foreground dark:hover:border-amber-500/40 dark:hover:bg-amber-500/20 dark:hover:text-foreground active:bg-amber-100 dark:active:bg-amber-500/20'
                    : 'border-amber-400/60 bg-background text-foreground hover:border-amber-400/60 hover:bg-background hover:text-foreground dark:border-amber-500/40 dark:hover:border-amber-500/40 active:bg-background',
                )}
                aria-pressed={filter === 'unread'}
                onClick={() => setFilter('unread')}
              >
                Non lues
                <span
                  className={cn(
                    'rounded-full px-2 py-0.5 text-[10px] font-semibold',
                    filter === 'unread'
                      ? 'bg-amber-200/70 text-amber-900 dark:bg-amber-500/25 dark:text-amber-50'
                      : 'bg-amber-100/70 text-amber-800 dark:bg-amber-500/15 dark:text-amber-100',
                  )}
                >
                  {unreadCount}
                </span>
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className={cn(
                  'rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em]',
                  filter === 'read'
                    ? 'border-emerald-500/60 bg-emerald-100 text-emerald-950 shadow-soft hover:border-emerald-500/60 hover:bg-emerald-100 hover:text-emerald-950 dark:border-emerald-400/50 dark:bg-emerald-500/20 dark:text-emerald-50 dark:hover:border-emerald-400/50 dark:hover:bg-emerald-500/20 dark:hover:text-emerald-50 active:bg-emerald-100 dark:active:bg-emerald-500/20'
                    : 'border-emerald-400/40 bg-background text-foreground hover:border-emerald-400/40 hover:bg-background hover:text-foreground dark:border-emerald-400/40 dark:hover:border-emerald-400/40 active:bg-background',
                )}
                aria-pressed={filter === 'read'}
                onClick={() => setFilter('read')}
              >
                Lues
                <span
                  className={cn(
                    'rounded-full px-2 py-0.5 text-[10px] font-semibold',
                    filter === 'read'
                      ? 'bg-emerald-200/70 text-emerald-900 dark:bg-emerald-500/25 dark:text-emerald-50'
                      : 'bg-emerald-100/70 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-100',
                  )}
                >
                  {readCount}
                </span>
              </Button>
            </div>
            {filteredNotifications.length === 0 ? (
              <Alert>
                <AlertTitle>Aucun resultat</AlertTitle>
                <AlertDescription>
                  {filter === 'unread'
                    ? "Vous n'avez aucune notification non lue."
                    : "Vous n'avez aucune notification lue."}
                </AlertDescription>
              </Alert>
            ) : (
              <div className="space-y-4">
                {filteredNotifications.map((item) => {
                  const createdLabel = formatDateTimeShort(item.created_at);
                  const isUnread = !item.is_read;
                  return (
                    <Link
                      key={item.id}
                      href={`/notifications/${item.id}`}
                      className="group block mb-6 last:mb-0"
                    >
                      <Card
                        className={cn(
                          'relative overflow-hidden border-border/70 bg-card/90 transition-all hover:-translate-y-0.5 hover:shadow-soft-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                          isUnread
                            ? 'border-l-4 border-l-[color:rgb(var(--palette-secondary-rgb)_/_0.8)] shadow-soft-lg'
                            : 'border-l-4 border-l-[color:rgb(var(--palette-primary-rgb)_/_0.8)] shadow-soft-lg',
                        )}
                      >
                        <CardHeader className="flex-row items-start justify-between gap-4">
                          <div className="space-y-2">
                            <div className="flex flex-wrap items-center gap-2">
                              {isUnread ? (
                                <Badge
                                  variant="secondary"
                                  tone="warning"
                                  className="!border-[color:rgb(var(--palette-secondary-rgb)_/_0.6)] !text-[color:rgb(var(--palette-secondary-rgb)_/_0.85)] dark:!border-[color:rgb(var(--palette-secondary-rgb)_/_0.7)] dark:!text-[color:rgb(var(--palette-secondary-rgb)_/_0.92)] pointer-events-none"
                                >
                                  Non lu
                                </Badge>
                              ) : (
                                <Badge
                                  variant="muted"
                                  tone="success"
                                  className="!border-[color:rgb(var(--palette-primary-rgb)_/_0.6)] !text-[color:rgb(var(--palette-primary-rgb)_/_0.85)] dark:!border-[color:rgb(var(--palette-primary-rgb)_/_0.7)] dark:!text-[color:rgb(var(--palette-primary-rgb)_/_0.92)] pointer-events-none"
                                >
                                  Lu
                                </Badge>
                              )}
                              {item.category ? (
                                <Badge variant="outline" className="pointer-events-none">
                                  {item.category}
                                </Badge>
                              ) : null}
                            </div>
                            <CardTitle className="text-lg">{item.title}</CardTitle>
                            {item.body ? (
                              <p className="line-clamp-2 text-sm text-muted-foreground">
                                {item.body}
                              </p>
                            ) : null}
                          </div>
                          <div className="flex flex-col items-end gap-2 text-right">
                            {createdLabel ? (
                              <span className="text-xs text-muted-foreground">{createdLabel}</span>
                            ) : null}
                            <span
                              className={cn(
                                'inline-flex h-8 w-8 items-center justify-center rounded-full border border-border/70 bg-surface-muted text-muted-foreground transition-colors',
                                'group-hover:text-foreground',
                              )}
                              aria-hidden="true"
                            >
                              <ChevronRight className="h-4 w-4" aria-hidden="true" />
                            </span>
                          </div>
                        </CardHeader>
                      </Card>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </main>
    </>
  );
}
