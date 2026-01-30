'use client';

import { Plus } from 'lucide-react';
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
import { createRole, fetchAssignablePermissions } from '../api/roles';
import type { RolePermission } from '../types/role-permission';

type RoleFormDialogProps = {
  onCreated?: () => void;
};

const toRoleCode = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '');

export function RoleFormDialog({ onCreated }: RoleFormDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [title, setTitle] = React.useState('');
  const [code, setCode] = React.useState('');
  const [codeTouched, setCodeTouched] = React.useState(false);
  const [description, setDescription] = React.useState('');
  const [permissions, setPermissions] = React.useState<RolePermission[]>([]);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [status, setStatus] = React.useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = React.useState('');
  const [isSubmitting, setIsSubmitting] = React.useState(false);

  const resetForm = React.useCallback(() => {
    setTitle('');
    setCode('');
    setCodeTouched(false);
    setDescription('');
    setSelected(new Set());
    setStatus('idle');
    setErrorMessage('');
  }, []);

  React.useEffect(() => {
    if (!open) {
      resetForm();
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
        setErrorMessage('Token manquant ou session expiree. Connectez-vous.');
        return;
      }

      try {
        setStatus('loading');
        const response = await fetchAssignablePermissions(token, controller.signal);
        setPermissions(mapPermissionsToRecords(response));
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
          setErrorMessage('Impossible de charger les permissions. Verifiez vos droits.');
        }
      }
    };

    loadPermissions();

    return () => controller.abort();
  }, [open, resetForm]);

  React.useEffect(() => {
    if (!codeTouched && title) {
      setCode(toRoleCode(title));
    }
  }, [title, codeTouched]);

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
    const trimmedCode = (code || toRoleCode(title)).trim();

    if (!trimmedTitle) {
      setErrorMessage('Le titre du role est obligatoire.');
      return;
    }

    if (!trimmedCode) {
      setErrorMessage('Le code du role est obligatoire.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage('');

    try {
      await createRole(token, {
        code: trimmedCode,
        name: trimmedTitle,
        description: description.trim() || undefined,
        permission_codes: Array.from(selected),
        is_assistant: true,
      });
      setOpen(false);
      onCreated?.();
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
        setErrorMessage('Creation impossible. Verifiez les donnees saisies.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button type="button" size="lg" className="items-center gap-3">
          <span className="flex items-center gap-3">
            <Plus className="h-5 w-5 translate-y-[1px]" aria-hidden="true" />
            <span className="whitespace-nowrap leading-tight">Ajouter un role</span>
          </span>
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[80vh] overflow-hidden p-6 sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>Creer un role</DialogTitle>
          <DialogDescription>
            Definissez un titre, une description et les permissions associees.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-5" onSubmit={handleSubmit}>
          <div className="max-h-[52vh] space-y-5 overflow-y-auto pr-3 scrollbar-subtle">
            <div className="space-y-2">
              <Label htmlFor="role-title">Titre du role</Label>
              <Input
                id="role-title"
                placeholder="Ex: Assistant"
                value={title}
                onChange={(event) => setTitle(event.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="role-code">Code du role</Label>
              <Input
                id="role-code"
                placeholder="Ex: assistant_ubs_lite"
                value={code}
                onChange={(event) => {
                  setCodeTouched(true);
                  setCode(event.target.value);
                }}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="role-description">Description</Label>
              <Textarea
                id="role-description"
                rows={3}
                placeholder="Decrivez les responsabilites principales."
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
                        id={permission.id}
                        checked={selected.has(permission.id)}
                        onCheckedChange={(checked) => handleToggle(permission.id, checked)}
                      />
                      <Label htmlFor={permission.id} className="space-y-1 text-sm">
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
