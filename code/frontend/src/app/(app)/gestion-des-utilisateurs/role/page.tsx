'use client';

import * as React from 'react';

import { Alert, AlertDescription, AlertTitle, Spinner } from '@/components';
import {
  deleteRole,
  fetchRoles,
  mapRolesToRecords,
  RoleActions,
  type RoleApi,
  RoleFormDialog,
  RolesTable,
  splitRoles,
} from '@/features/gestion-des-utilisateurs';
import { ApiError, type CurrentUser, fetchCurrentUser } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import {
  isAdminRole,
  isSuperAdminRole,
  normalizeRoleCode,
  resolveAssistantStatus,
} from '@/lib/roles';

export default function UsersRolesPage() {
  const [roles, setRoles] = React.useState<RoleApi[]>([]);
  const [currentUser, setCurrentUser] = React.useState<CurrentUser | null>(null);
  const [status, setStatus] = React.useState<'loading' | 'success' | 'error' | 'forbidden'>(
    'loading',
  );
  const [error, setError] = React.useState('');
  const [actionStatus, setActionStatus] = React.useState<'idle' | 'success' | 'error'>('idle');
  const [actionMessage, setActionMessage] = React.useState('');

  const loadRoles = React.useCallback(async (signal?: AbortSignal, silent = false) => {
    if (!silent) {
      setStatus('loading');
      setError('');
    }
    try {
      const token = getAccessToken() ?? undefined;
      if (!token) {
        if (silent) {
          setActionStatus('error');
          setActionMessage('Token manquant ou session expiree. Connectez-vous.');
        } else {
          setStatus('error');
          setError('Token manquant ou session expiree. Connectez-vous.');
        }
        return;
      }
      const user = await fetchCurrentUser(token, signal);
      setCurrentUser(user);
      const roleKey = normalizeRoleCode(user.role);
      const response = await fetchRoles(token, signal);
      const roleMatch = roleKey ? resolveAssistantStatus(roleKey, response) : undefined;
      const isAssistant = roleKey
        ? typeof roleMatch === 'boolean'
          ? roleMatch
          : roleKey.startsWith('assistant')
        : true;
      if (isAssistant) {
        if (!silent) {
          setStatus('forbidden');
          setError('Acces reserve aux administrateurs.');
        }
        return;
      }
      setRoles(response);
      if (!silent) {
        setStatus('success');
      }
    } catch (fetchError) {
      if (signal?.aborted) {
        return;
      }
      if (!silent) {
        setStatus('error');
      }
      if (fetchError instanceof ApiError) {
        if (fetchError.status === 401) {
          if (silent) {
            setActionStatus('error');
            setActionMessage('Session invalide ou expiree. Reconnectez-vous.');
          } else {
            setError('Session invalide ou expiree. Reconnectez-vous.');
          }
        } else if (fetchError.status === 403) {
          if (silent) {
            setActionStatus('error');
            setActionMessage('Acces refuse. Verifiez vos droits.');
          } else {
            setError('Acces refuse. Verifiez vos droits.');
          }
        } else {
          if (silent) {
            setActionStatus('error');
            setActionMessage(fetchError.message);
          } else {
            setError(fetchError.message);
          }
        }
      } else {
        if (silent) {
          setActionStatus('error');
          setActionMessage("Impossible de charger les roles. Verifiez l'API.");
        } else {
          setError("Impossible de charger les roles. Verifiez l'API.");
        }
      }
    }
  }, []);

  React.useEffect(() => {
    const controller = new AbortController();
    loadRoles(controller.signal);
    return () => controller.abort();
  }, [loadRoles]);

  const { defaultRoles, assistantRoles } = React.useMemo(() => splitRoles(roles), [roles]);

  const defaultRoleRows = React.useMemo(() => mapRolesToRecords(defaultRoles), [defaultRoles]);
  const assistantRoleRows = React.useMemo(
    () => mapRolesToRecords(assistantRoles),
    [assistantRoles],
  );

  const roleKey = React.useMemo(() => normalizeRoleCode(currentUser?.role), [currentUser]);
  const isSuperAdmin = isSuperAdminRole(roleKey);
  const isAdmin = isAdminRole(roleKey);

  const canManageRole = React.useCallback(
    (role: { createdById?: number | null }) => {
      if (!currentUser) {
        return false;
      }
      if (isSuperAdmin) {
        return true;
      }
      if (!isAdmin) {
        return false;
      }
      const creatorId = Number(role.createdById);
      if (!Number.isFinite(creatorId)) {
        return false;
      }
      return creatorId === currentUser.id;
    },
    [currentUser, isSuperAdmin, isAdmin],
  );

  const handleDeleteRole = React.useCallback(async (role: { code: string; name: string }) => {
    if (typeof window === 'undefined') {
      return;
    }
    const token = getAccessToken();
    if (!token) {
      setActionStatus('error');
      setActionMessage('Token manquant ou session expiree. Connectez-vous.');
      return;
    }

    setActionStatus('idle');
    setActionMessage('');
    try {
      const response = await deleteRole(token, role.code);
      setRoles((prev) => prev.filter((entry) => entry.code !== role.code));
      setActionStatus('success');
      setActionMessage(response.message || 'Role supprime.');
    } catch (fetchError) {
      setActionStatus('error');
      if (fetchError instanceof ApiError) {
        if (fetchError.status === 401) {
          setActionMessage('Session invalide ou expiree. Reconnectez-vous.');
        } else if (fetchError.status === 403) {
          setActionMessage('Acces refuse. Verifiez vos droits.');
        } else {
          setActionMessage(fetchError.message);
        }
      } else {
        setActionMessage('Suppression impossible. Verifiez vos droits.');
      }
    }
  }, []);

  const handleRoleUpdated = React.useCallback(() => {
    setActionStatus('idle');
    setActionMessage('');
    loadRoles(undefined, true);
  }, [loadRoles]);

  return (
    <main className="mt-6 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
      {status === 'forbidden' ? (
        <Alert variant="destructive">
          <AlertTitle>Acces refuse</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : (
        <>
          {status === 'success' ? (
            <div className="flex items-center justify-start">
              <RoleFormDialog onCreated={() => loadRoles()} />
            </div>
          ) : null}

          <div className="mt-6">
            {status === 'loading' ? (
              <div className="flex min-h-[240px] items-center justify-center">
                <Spinner size="lg" />
              </div>
            ) : status === 'error' ? (
              <Alert variant="destructive">
                <AlertTitle>Chargement impossible</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : (
              <div className="space-y-6">
                {actionStatus !== 'idle' && actionMessage ? (
                  <Alert variant={actionStatus === 'error' ? 'destructive' : 'default'}>
                    <AlertTitle>
                      {actionStatus === 'error' ? 'Suppression impossible' : 'Role supprime'}
                    </AlertTitle>
                    <AlertDescription>{actionMessage}</AlertDescription>
                  </Alert>
                ) : null}
                {defaultRoleRows.length > 0 && (
                  <RolesTable title="Roles par defaut" rows={defaultRoleRows} />
                )}
                {assistantRoleRows.length > 0 && (
                  <RolesTable
                    title="Roles assistants crees"
                    rows={assistantRoleRows}
                    renderActions={(role) => (
                      <RoleActions
                        role={role}
                        canManage={canManageRole(role)}
                        onDelete={handleDeleteRole}
                        onUpdated={handleRoleUpdated}
                      />
                    )}
                  />
                )}
                {roles.length === 0 && (
                  <Alert>
                    <AlertTitle>Aucun role</AlertTitle>
                    <AlertDescription>
                      Aucun role n&apos;est disponible pour le moment.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </main>
  );
}
