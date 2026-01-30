'use client';
import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Card,
  CardHeader,
  CardTitle,
  PageHeader,
  Spinner,
} from '@/components';
import { ApiError, fetchHistory, type HistoryApi } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import { formatDateTimeShort } from '@/lib/formatters';
import { formatRoleLabel } from '@/lib/roles';
const resolveActionLabel = (action: string) => {
  const labels: Record<string, string> = {
    'user.create': 'Creation utilisateur',
    'user.update': 'Mise a jour utilisateur',
    'assistant.delete': 'Suppression assistant',
    'role.create': 'Creation role',
    'role.update': 'Mise a jour role',
    'role.permissions.update': 'Permissions role',
    'role.delete': 'Suppression role',
  };
  return labels[action] ?? action.replace(/\./g, ' ');
};
const isUserAction = (item: HistoryApi) => {
  const action = item.action ?? '';
  const entity = item.entity_type ?? '';
  return action.startsWith('user.') || action.startsWith('assistant.') || entity === 'user';
};
const isRoleAction = (item: HistoryApi) => {
  const action = item.action ?? '';
  const entity = item.entity_type ?? '';
  return action.startsWith('role.') || entity === 'role';
};
const resolveCategory = (item: HistoryApi) => {
  if ((item.action ?? '').startsWith('assistant.')) {
    return 'Assistant';
  }
  if (isRoleAction(item)) {
    return 'Role';
  }
  if (isUserAction(item)) {
    return 'Utilisateur';
  }
  return 'Action';
};
const buildMetaLines = (meta?: Record<string, unknown> | null) => {
  if (!meta || typeof meta !== 'object') {
    return [];
  }
  const lines: string[] = [];
  if (typeof meta.email === 'string') {
    lines.push(`Email: ${meta.email}`);
  }
  if (typeof meta.role === 'string') {
    lines.push(`Role: ${formatRoleLabel(meta.role)}`);
  }
  if (typeof meta.role_code === 'string') {
    lines.push(`Code role: ${meta.role_code}`);
  }
  if (Array.isArray(meta.fields) && meta.fields.length > 0) {
    lines.push(`Champs: ${meta.fields.join(', ')}`);
  }
  if (Array.isArray(meta.permission_codes) && meta.permission_codes.length > 0) {
    lines.push(`Permissions: ${meta.permission_codes.length}`);
  }
  return lines;
};
export default function HistoriquePage() {
  const [history, setHistory] = React.useState<HistoryApi[]>([]);
  const [status, setStatus] = React.useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = React.useState('');
  React.useEffect(() => {
    const controller = new AbortController();
    const pollIntervalMs = 30_000;
    const loadHistory = async ({ silent = false } = {}) => {
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
        const response = await fetchHistory(token, { limit: 200 }, controller.signal);
        setHistory(response);
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
            setError("Impossible de charger l'historique.");
          }
        }
      }
    };
    loadHistory();
    const pollId = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        loadHistory({ silent: true });
      }
    }, pollIntervalMs);
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        loadHistory({ silent: true });
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleVisibilityChange);
    return () => {
      window.clearInterval(pollId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleVisibilityChange);
      controller.abort();
    };
  }, []);
  return (
    <>
      <PageHeader
        title="Historique"
        description="Consultez toutes les actions tracees dans le systeme."
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
        ) : history.length === 0 ? (
          <Alert>
            <AlertTitle>Aucune entree</AlertTitle>
            <AlertDescription>
              Aucun historique n&apos;est disponible pour le moment.
            </AlertDescription>
          </Alert>
        ) : (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-border/60 bg-surface-muted/70 px-5 py-4">
              <div>
                <p className="text-sm font-semibold text-foreground">Historique recent</p>
                <p className="text-xs text-muted-foreground">
                  {history.length} action {history.length > 1 ? 's' : ''} enregistree
                  {history.length > 1 ? 's' : ''}
                </p>
              </div>
            </div>
            <div className="space-y-4">
              {history.map((item) => {
                const createdLabel = formatDateTimeShort(item.created_at);
                const actionLabel = resolveActionLabel(item.action);
                const categoryLabel = resolveCategory(item);
                const moduleLabel = item.module ? item.module.toUpperCase() : null;
                const title =
                  item.description && item.description.trim().length > 0
                    ? item.description
                    : actionLabel;
                const actorRole = formatRoleLabel(item.actor_role);
                const actorLabel = actorRole || (item.actor_id ? 'Utilisateur' : '');
                const actorInfo = [actorLabel, item.actor_id ? `#${item.actor_id}` : null]
                  .filter(Boolean)
                  .join(' ');
                const metaLines = buildMetaLines(item.meta ?? null);
                return (
                  <Card key={item.id} className="border-border/70 bg-card/90 shadow-soft-lg">
                    <CardHeader className="flex-row items-start justify-between gap-4">
                      <div className="space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge
                            variant={categoryLabel === 'Role' ? 'muted' : 'secondary'}
                            tone={
                              categoryLabel === 'Assistant'
                                ? 'warning'
                                : categoryLabel === 'Role'
                                  ? 'success'
                                  : 'info'
                            }
                            className="pointer-events-none"
                          >
                            {categoryLabel}
                          </Badge>
                          <Badge variant="outline" className="pointer-events-none">
                            {actionLabel}
                          </Badge>
                          {moduleLabel ? (
                            <Badge variant="outline" className="pointer-events-none">
                              {moduleLabel}
                            </Badge>
                          ) : null}
                        </div>
                        <CardTitle className="text-lg">{title}</CardTitle>
                        {metaLines.length > 0 ? (
                          <div className="space-y-1 text-xs text-muted-foreground">
                            {metaLines.map((line) => (
                              <div key={line}>{line}</div>
                            ))}
                          </div>
                        ) : null}
                      </div>
                      <div className="flex flex-col items-end gap-2 text-right">
                        {createdLabel ? (
                          <span className="text-xs text-muted-foreground">{createdLabel}</span>
                        ) : null}
                        {actorInfo ? (
                          <span className="text-xs text-muted-foreground">Par {actorInfo}</span>
                        ) : null}
                      </div>
                    </CardHeader>
                  </Card>
                );
              })}
            </div>
          </div>
        )}
      </main>
    </>
  );
}
