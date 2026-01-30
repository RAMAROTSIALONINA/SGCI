'use client';

import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Checkbox,
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Input,
  Label,
  Textarea,
} from '@/components';
import { ApiError } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';

import { mapPermissionsToRecords } from '../adapters';
import { fetchAssignablePermissions, fetchRolePermissions, updateRole } from '../api/roles';
import type { RolePermission } from '../types/role-permission';
import type { RoleRecord } from '../types/role-record';

type RoleEditDialogProps = {
  role: RoleRecord;
  onUpdated?: () => void;
};

export function RoleEditDialog({ role, onUpdated }: RoleEditDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [title, setTitle] = React.useState(role.name);
  const [description, setDescription] = React.useState(role.description ?? '');
  const [permissions, setPermissions] = React.useState<RolePermission[]>([]);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [status, setStatus] = React.useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = React.useState('');
  const [isSubmitting, setIsSubmitting] = React.useState(false);

  React.useEffect(() => {
    if (!open) {
      setStatus('idle');
      setErrorMessage('');
      setPermissions([]);
      setSelected(new Set());
      return;
    }

    setTitle(role.name);
    setDescription(role.description ?? '');

    const controller = new AbortController();

    const loadPermissions = async () => {
      if (typeof window === 'undefined') {
        return;
      }

      const token = getAccessToken();
      if (!token) {
        setStatus('error');
        setErrorMessage('Token manquant ou session expiree. Connectez-vous.');
        return;
      }

      try {
        setStatus('loading');
        const [assignable, current] = await Promise.all([
          fetchAssignablePermissions(token, controller.signal),
          fetchRolePermissions(token, role.code, controller.signal),
        ]);
        const mapped = mapPermissionsToRecords(assignable);
        const currentIds = new Set(current.map((permission) => permission.code));
        setPermissions(mapped);
        setSelected(
          new Set(mapped.filter((perm) => currentIds.has(perm.id)).map((perm) => perm.id)),
        );
        setStatus('ready');
      } catch (error) {
        if (controller.signal.aborted) {
          return;
        }
        setStatus('error');
        if (error instanceof ApiError) {
          if (error.status === 401) {
            setErrorMessage('Session invalide ou expiree. Reconnectez-vous.');
          } else if (error.status === 403) {
            setErrorMessage('Acces refuse. Verifiez vos droits.');
          } else {
            setErrorMessage(error.message);
          }
        } else {
          setErrorMessage('Impossible de charger les permissions du role.');
        }
      }
    };

    loadPermissions();

    return () => controller.abort();
  }, [open, role]);

  const handleToggle = (permissionId: string, checked: boolean | 'indeterminate') => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked === true) {
        next.add(permissionId);
      } else {
        next.delete(permissionId);
      }
      return next;
    });
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (typeof window === 'undefined') {
      return;
    }

    const token = getAccessToken();
    if (!token) {
      setErrorMessage('Token manquant ou session expiree. Connectez-vous.');
      return;
    }

    const trimmedTitle = title.trim();
    if (!trimmedTitle) {
      setErrorMessage('Le titre du role est obligatoire.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage('');

    try {
      await updateRole(token, role.code, {
        name: trimmedTitle,
        description: description.trim() || undefined,
        permission_codes: Array.from(selected),
      });
      setOpen(false);
      onUpdated?.();
    } catch (error) {
      if (error instanceof ApiError) {
        if (error.status === 401) {
          setErrorMessage('Session invalide ou expiree. Reconnectez-vous.');
        } else if (error.status === 403) {
          setErrorMessage('Acces refuse. Verifiez vos droits.');
        } else {
          setErrorMessage(error.message);
        }
      } else {
        setErrorMessage('Mise a jour impossible. Verifiez les donnees saisies.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen} modal={false}>
      <DialogTrigger asChild>
        <Button type="button" size="sm" variant="outline">
          Modifier
        </Button>
      </DialogTrigger>
      <DialogContent
        className="max-h-[80vh] overflow-hidden p-6 sm:max-w-[520px]"
        onOpenAutoFocus={(event) => event.preventDefault()}
        onCloseAutoFocus={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>Modifier le role</DialogTitle>
          <DialogDescription>
            Ajustez le titre, la description et les permissions associees.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-5" onSubmit={handleSubmit}>
          <div className="max-h-[52vh] space-y-5 overflow-y-auto pr-3 scrollbar-subtle">
            <div className="space-y-2">
              <Label htmlFor={`role-title-${role.id}`}>Titre du role</Label>
              <Input
                id={`role-title-${role.id}`}
                value={title}
                onChange={(event) => setTitle(event.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor={`role-code-${role.id}`}>Code du role</Label>
              <Input id={`role-code-${role.id}`} value={role.code} disabled />
            </div>

            <div className="space-y-2">
              <Label htmlFor={`role-description-${role.id}`}>Description</Label>
              <Textarea
                id={`role-description-${role.id}`}
                rows={3}
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </div>

            <div className="space-y-3 rounded-2xl border border-border/60 bg-surface/60 p-4">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-semibold text-foreground">Fonctionnalites</Label>
                <span className="text-xs text-muted-foreground">Choisir les permissions</span>
              </div>
              {status === 'loading' ? (
                <div className="text-xs text-muted-foreground">Chargement des permissions...</div>
              ) : status === 'error' ? (
                <div className="text-xs text-destructive">{errorMessage}</div>
              ) : (
                <div className="grid gap-3 sm:grid-cols-2">
                  {permissions.map((permission) => (
                    <div
                      key={permission.id}
                      className="flex items-start gap-3 rounded-xl border border-border/70 bg-background/40 px-3 py-2"
                    >
                      <Checkbox
                        id={`${role.id}-${permission.id}`}
                        checked={selected.has(permission.id)}
                        onCheckedChange={(checked) => handleToggle(permission.id, checked)}
                      />
                      <Label htmlFor={`${role.id}-${permission.id}`} className="space-y-1 text-sm">
                        <span className="font-medium text-foreground">{permission.label}</span>
                        {permission.description && (
                          <span className="block text-xs text-muted-foreground">
                            {permission.description}
                          </span>
                        )}
                      </Label>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {errorMessage && status !== 'error' ? (
            <Alert variant="destructive">
              <AlertTitle>Erreur</AlertTitle>
              <AlertDescription>{errorMessage}</AlertDescription>
            </Alert>
          ) : null}

          <DialogFooter className="pt-2">
            <DialogClose asChild>
              <Button type="button" variant="ghost">
                Annuler
              </Button>
            </DialogClose>
            <Button type="submit" isLoading={isSubmitting} disabled={status !== 'ready'}>
              Enregistrer
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
