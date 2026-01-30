'use client';

import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Spinner,
} from '@/components';
import { ApiError } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';

import { mapPermissionsToRecords } from '../adapters';
import { fetchRolePermissions } from '../api/roles';
import type { RolePermission } from '../types/role-permission';
import type { RoleRecord } from '../types/role-record';

type RolePermissionsDialogProps = {
  role: RoleRecord;
};

export function RolePermissionsDialog({ role }: RolePermissionsDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [status, setStatus] = React.useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [permissions, setPermissions] = React.useState<RolePermission[]>([]);
  const [message, setMessage] = React.useState('');

  React.useEffect(() => {
    if (!open) {
      setStatus('idle');
      setPermissions([]);
      setMessage('');
      return;
    }

    const controller = new AbortController();

    const loadPermissions = async () => {
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
        setStatus('loading');
        const response = await fetchRolePermissions(token, role.code, controller.signal);
        setPermissions(mapPermissionsToRecords(response));
        setStatus('success');
      } catch (error) {
        if (controller.signal.aborted) {
          return;
        }
        setStatus('error');
        if (error instanceof ApiError) {
          if (error.status === 401) {
            setMessage('Session invalide ou expiree. Reconnectez-vous.');
          } else if (error.status === 403) {
            setMessage('Acces refuse. Verifiez vos droits.');
          } else {
            setMessage(error.message);
          }
        } else {
          setMessage('Impossible de charger les permissions du role.');
        }
      }
    };

    loadPermissions();

    return () => controller.abort();
  }, [open, role.code]);

  return (
    <Dialog open={open} onOpenChange={setOpen} modal={false}>
      <DialogTrigger asChild>
        <Button type="button" size="sm" variant="secondary">
          Voir les permissions
        </Button>
      </DialogTrigger>
      <DialogContent
        className="max-h-[80vh] overflow-hidden p-6 sm:max-w-[560px]"
        onOpenAutoFocus={(event) => event.preventDefault()}
        onCloseAutoFocus={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>Permissions du role</DialogTitle>
          <DialogDescription>
            <span className="font-semibold text-foreground">{role.name}</span>
            {role.code ? (
              <span className="ml-2 text-xs text-muted-foreground">({role.code})</span>
            ) : null}
          </DialogDescription>
        </DialogHeader>

        <div className="mt-4 space-y-4">
          {status === 'loading' ? (
            <div className="flex min-h-[200px] items-center justify-center">
              <Spinner size="lg" />
            </div>
          ) : status === 'error' ? (
            <Alert variant="destructive">
              <AlertTitle>Chargement impossible</AlertTitle>
              <AlertDescription>{message}</AlertDescription>
            </Alert>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-foreground">Liste des permissions</span>
                <Badge variant="secondary">
                  {permissions.length} element{permissions.length > 1 ? 's' : ''}
                </Badge>
              </div>
              {permissions.length === 0 ? (
                <div className="rounded-2xl border border-border/70 bg-surface/60 p-4 text-sm text-muted-foreground">
                  Aucune permission associee a ce role pour le moment.
                </div>
              ) : (
                <div className="grid gap-3 sm:grid-cols-2">
                  {permissions.map((permission) => (
                    <div
                      key={permission.id}
                      className="rounded-2xl border border-border/70 bg-background/50 p-3"
                    >
                      <p className="text-sm font-semibold text-foreground">{permission.label}</p>
                      {permission.description ? (
                        <p className="mt-1 text-xs text-muted-foreground">
                          {permission.description}
                        </p>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
