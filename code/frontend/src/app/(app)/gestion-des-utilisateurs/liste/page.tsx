'use client';

import * as React from 'react';

import { Alert, AlertDescription, AlertTitle, Spinner } from '@/components';
import {
  buildRoleLookup,
  deleteAssistant,
  fetchRoles,
  fetchUsers,
  groupUsersByRole,
  mapUsersToRecords,
  type RoleApi,
  type UserApi,
  UserFormDialog,
  type UserRecord,
  UsersTable,
} from '@/features/gestion-des-utilisateurs';
import { ApiError, type CurrentUser, fetchCurrentUser } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import { isAdminRole, isSuperAdminRole, normalizeRole } from '@/lib/roles';

export default function UsersListPage() {
  const [users, setUsers] = React.useState<UserApi[]>([]);
  const [roles, setRoles] = React.useState<RoleApi[]>([]);
  const [currentUser, setCurrentUser] = React.useState<CurrentUser | null>(null);
  const [status, setStatus] = React.useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = React.useState('');
  const [actionStatus, setActionStatus] = React.useState<'idle' | 'success' | 'error'>('idle');
  const [actionTitle, setActionTitle] = React.useState('');
  const [actionMessage, setActionMessage] = React.useState('');

  const loadUsers = React.useCallback(async (signal?: AbortSignal, silent = false) => {
    if (typeof window === 'undefined') {
      return;
    }

    if (!silent) {
      setStatus('loading');
      setError('');
    }

    const token = getAccessToken();
    if (!token) {
      if (silent) {
        setActionStatus('error');
        setActionTitle('Actualisation impossible');
        setActionMessage('Token manquant ou session expiree. Connectez-vous.');
      } else {
        setStatus('error');
        setError('Token manquant ou session expiree. Connectez-vous.');
      }
      return;
    }

    try {
      const [user, response] = await Promise.all([
        fetchCurrentUser(token, signal),
        fetchUsers(token, signal),
      ]);
      setCurrentUser(user);
      setUsers(response);
      try {
        const rolesResponse = await fetchRoles(token, signal);
        setRoles(rolesResponse);
      } catch {
        setRoles([]);
      }
      setStatus('success');
    } catch (fetchError) {
      if (signal?.aborted) {
        return;
      }

      if (silent) {
        setActionStatus('error');
        setActionTitle('Actualisation impossible');
        if (fetchError instanceof ApiError) {
          if (fetchError.status === 401) {
            setActionMessage('Session invalide ou expiree. Reconnectez-vous.');
          } else if (fetchError.status === 403) {
            setActionMessage('Acces refuse. Verifiez vos droits.');
          } else {
            setActionMessage(fetchError.message);
          }
        } else {
          setActionMessage('Impossible de charger les utilisateurs. Verifiez vos droits.');
        }
      } else {
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
          setError('Impossible de charger les utilisateurs. Verifiez vos droits.');
        }
      }
    }
  }, []);

  React.useEffect(() => {
    const controller = new AbortController();
    loadUsers(controller.signal);
    return () => controller.abort();
  }, [loadUsers]);

  const roleKey = React.useMemo(() => normalizeRole(currentUser?.role), [currentUser]);
  const roleLookup = React.useMemo(() => buildRoleLookup(roles), [roles]);
  const isSuperAdmin = isSuperAdminRole(roleKey);
  const canShowDelete = Boolean(currentUser) && isAdminRole(roleKey);
  const canDeleteAssistant = React.useCallback(
    (user: UserApi) => {
      if (!currentUser) {
        return false;
      }
      if (isSuperAdmin) {
        return true;
      }
      if (!isAdminRole(roleKey)) {
        return false;
      }
      const creatorId = Number(user.created_by_id);
      if (!Number.isFinite(creatorId)) {
        return false;
      }
      return creatorId === currentUser.id;
    },
    [currentUser, isSuperAdmin, roleKey],
  );

  const handleDelete = React.useCallback(async (user: UserRecord) => {
    if (typeof window === 'undefined') {
      return;
    }
    const token = getAccessToken();
    if (!token) {
      setActionStatus('error');
      setActionTitle('Suppression impossible');
      setActionMessage('Token manquant ou session expiree. Connectez-vous.');
      return;
    }
    const userId = Number(user.id);
    if (!Number.isFinite(userId)) {
      setActionStatus('error');
      setActionTitle('Suppression impossible');
      setActionMessage('Identifiant utilisateur invalide.');
      return;
    }

    setActionStatus('idle');
    setActionTitle('');
    setActionMessage('');
    try {
      const response = await deleteAssistant(token, userId);
      setUsers((prev) => prev.filter((entry) => entry.id !== userId));
      setActionStatus('success');
      setActionTitle('Assistant supprime');
      setActionMessage(response.message || 'Assistant supprime.');
    } catch (fetchError) {
      setActionStatus('error');
      setActionTitle('Suppression impossible');
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

  const handleUserCreated = React.useCallback(
    (message?: string) => {
      setActionStatus('success');
      setActionTitle('Utilisateur cree');
      setActionMessage(message || 'Utilisateur cree.');
      loadUsers(undefined, true);
    },
    [loadUsers],
  );

  const groupedUsers = React.useMemo(
    () => groupUsersByRole(users, roleLookup),
    [users, roleLookup],
  );
  const adminAndSuperAdminRows = React.useMemo(
    () => mapUsersToRecords([...groupedUsers.superAdmins, ...groupedUsers.admins]),
    [groupedUsers.admins, groupedUsers.superAdmins],
  );
  const assistants = React.useMemo(
    () => mapUsersToRecords(groupedUsers.assistants, canDeleteAssistant),
    [groupedUsers.assistants, canDeleteAssistant],
  );
  const others = React.useMemo(() => mapUsersToRecords(groupedUsers.others), [groupedUsers.others]);

  return (
    <main className="mt-6 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
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
          <div className="flex items-center justify-start">
            <UserFormDialog onCreated={handleUserCreated} />
          </div>
          {actionStatus !== 'idle' && actionMessage ? (
            <Alert variant={actionStatus === 'error' ? 'destructive' : 'default'}>
              <AlertTitle>
                {actionTitle || (actionStatus === 'error' ? 'Action impossible' : 'Action reussie')}
              </AlertTitle>
              <AlertDescription>{actionMessage}</AlertDescription>
            </Alert>
          ) : null}
          {adminAndSuperAdminRows.length > 0 && (
            <UsersTable title="Admins" rows={adminAndSuperAdminRows} />
          )}
          {assistants.length > 0 && (
            <UsersTable
              title="Assistants"
              rows={assistants}
              showDelete={canShowDelete}
              onDelete={handleDelete}
            />
          )}
          {others.length > 0 && <UsersTable title="Autres" rows={others} />}
          {users.length === 0 && (
            <Alert>
              <AlertTitle>Aucun utilisateur</AlertTitle>
              <AlertDescription>
                Aucun compte n&apos;est disponible pour le moment.
              </AlertDescription>
            </Alert>
          )}
        </div>
      )}
    </main>
  );
}
