'use client';

import { Plus } from 'lucide-react';
import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components';
import { ApiError, type CurrentUser, fetchCurrentUser, signupAssistant } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import { isSuperAdminRole, normalizeRoleCode } from '@/lib/roles';

import { fetchRoles } from '../api/roles';
import type { RoleApi } from '../types/api';

type UserFormDialogProps = {
  onCreated?: (message?: string) => void;
};

export function UserFormDialog({ onCreated }: UserFormDialogProps) {
  const [open, setOpen] = React.useState(false);
  const [firstName, setFirstName] = React.useState('');
  const [lastName, setLastName] = React.useState('');
  const [email, setEmail] = React.useState('');
  const [roleCode, setRoleCode] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [roles, setRoles] = React.useState<RoleApi[]>([]);
  const [currentUser, setCurrentUser] = React.useState<CurrentUser | null>(null);
  const [rolesStatus, setRolesStatus] = React.useState<'loading' | 'success' | 'error'>('loading');
  const [rolesError, setRolesError] = React.useState('');
  const [errorMessage, setErrorMessage] = React.useState('');
  const [isSubmitting, setIsSubmitting] = React.useState(false);

  const resetForm = React.useCallback(() => {
    setFirstName('');
    setLastName('');
    setEmail('');
    setRoleCode('');
    setPassword('');
    setErrorMessage('');
    setIsSubmitting(false);
  }, []);

  React.useEffect(() => {
    if (!open) {
      resetForm();
      return;
    }

    const controller = new AbortController();

    const loadRoles = async () => {
      if (typeof window === 'undefined') {
        return;
      }
      setRolesStatus('loading');
      setRolesError('');
      try {
        const token = getAccessToken() ?? undefined;
        const [user, response] = await Promise.all([
          token ? fetchCurrentUser(token, controller.signal) : Promise.resolve(null),
          fetchRoles(token, controller.signal),
        ]);
        setCurrentUser(user);
        setRoles(response);
        setRolesStatus('success');
      } catch {
        if (controller.signal.aborted) {
          return;
        }
        setRoles([]);
        setRolesStatus('error');
        setRolesError('Impossible de charger les roles.');
      }
    };

    loadRoles();

    return () => controller.abort();
  }, [open, resetForm]);

  const roleKey = React.useMemo(() => normalizeRoleCode(currentUser?.role), [currentUser]);
  const isSuperAdmin = isSuperAdminRole(roleKey);
  const selectableRoles = React.useMemo(() => {
    if (isSuperAdmin) {
      return roles;
    }
    const currentUserId = currentUser?.id;
    if (!currentUserId) {
      return [];
    }
    return roles.filter((role) => role.is_assistant && role.created_by_id === currentUserId);
  }, [currentUser, isSuperAdmin, roles]);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (typeof window === 'undefined') {
      return;
    }

    setErrorMessage('');
    const token = getAccessToken();
    if (!token) {
      setErrorMessage('Token manquant ou session expiree. Connectez-vous.');
      return;
    }

    if (!firstName.trim() || !lastName.trim() || !email.trim()) {
      setErrorMessage('Veuillez renseigner tous les champs requis.');
      return;
    }

    if (!roleCode) {
      setErrorMessage('Veuillez selectionner un role.');
      return;
    }

    if (!password.trim()) {
      setErrorMessage('Veuillez definir un mot de passe provisoire.');
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await signupAssistant(token, {
        first_name: firstName.trim(),
        last_name: lastName.trim(),
        email: email.trim(),
        password: password.trim(),
        role_code: roleCode,
      });
      setOpen(false);
      onCreated?.(response.message);
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
            <span className="whitespace-nowrap leading-tight">Ajouter un utilisateur</span>
          </span>
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-hidden p-6 sm:max-w-[620px]">
        <DialogHeader>
          <DialogTitle>Nouvel utilisateur</DialogTitle>
          <DialogDescription>
            Renseignez les informations essentielles pour creer un compte utilisateur.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-5 px-3 sm:px-4" onSubmit={handleSubmit}>
          <div className="max-h-[60vh] space-y-5 overflow-y-auto pr-3 scrollbar-subtle">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="new-user-last-name">Nom</Label>
                <Input
                  id="new-user-last-name"
                  placeholder="Ex: Dupont"
                  value={lastName}
                  onChange={(event) => setLastName(event.target.value)}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="new-user-first-name">Prenom</Label>
                <Input
                  id="new-user-first-name"
                  placeholder="Ex: Amina"
                  value={firstName}
                  onChange={(event) => setFirstName(event.target.value)}
                />
              </div>

              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="new-user-email">Email</Label>
                <Input
                  id="new-user-email"
                  type="email"
                  placeholder="nom@entreprise.com"
                  autoComplete="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
              </div>

              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="new-user-role">Role utilisateur</Label>
                <Select
                  value={roleCode}
                  onValueChange={setRoleCode}
                  disabled={rolesStatus !== 'success'}
                >
                  <SelectTrigger id="new-user-role">
                    <SelectValue placeholder="Selectionner un role" />
                  </SelectTrigger>
                  <SelectContent>
                    {rolesStatus === 'loading' ? (
                      <SelectItem value="loading" disabled>
                        Chargement des roles...
                      </SelectItem>
                    ) : rolesStatus === 'error' ? (
                      <SelectItem value="error" disabled>
                        {rolesError}
                      </SelectItem>
                    ) : selectableRoles.length > 0 ? (
                      selectableRoles.map((role) => (
                        <SelectItem key={role.code} value={role.code}>
                          {role.name}
                        </SelectItem>
                      ))
                    ) : (
                      <SelectItem value="empty" disabled>
                        Aucun role disponible.
                      </SelectItem>
                    )}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="new-user-password">Mot de passe</Label>
                <Input
                  id="new-user-password"
                  type="password"
                  placeholder="Definir un mot de passe provisoire"
                  autoComplete="new-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
                <span className="text-xs text-muted-foreground">
                  L&apos;utilisateur pourra changer ce mot de passe a sa premiere connexion.
                </span>
              </div>
            </div>

            {errorMessage ? (
              <Alert variant="destructive">
                <AlertTitle>Creation impossible</AlertTitle>
                <AlertDescription>{errorMessage}</AlertDescription>
              </Alert>
            ) : null}
          </div>

          <DialogFooter className="pt-2">
            <DialogClose asChild>
              <Button type="button" variant="ghost">
                Annuler
              </Button>
            </DialogClose>
            <Button type="submit" isLoading={isSubmitting}>
              Creer l&apos;utilisateur
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
