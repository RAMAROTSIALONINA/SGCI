'use client';

import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  Input,
  Label,
  Spinner,
} from '@/components';
import { ApiError, fetchCurrentUser, updateCurrentUser } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';

export default function SettingsProfilePage() {
  const [firstName, setFirstName] = React.useState('');
  const [lastName, setLastName] = React.useState('');
  const [email, setEmail] = React.useState('');
  const [currentPassword, setCurrentPassword] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [confirmPassword, setConfirmPassword] = React.useState('');
  const [status, setStatus] = React.useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = React.useState('');
  const [isLoadingUser, setIsLoadingUser] = React.useState(true);

  React.useEffect(() => {
    const controller = new AbortController();

    const loadUser = async () => {
      if (typeof window === 'undefined') {
        return;
      }
      const token = getAccessToken();
      if (!token) {
        setIsLoadingUser(false);
        setStatus('error');
        setMessage('Token manquant ou session expiree. Connectez-vous.');
        return;
      }

      try {
        const user = await fetchCurrentUser(token, controller.signal);
        setFirstName(user.first_name);
        setLastName(user.last_name);
        setEmail(user.email);
        setIsLoadingUser(false);
      } catch {
        if (controller.signal.aborted) {
          return;
        }
        setIsLoadingUser(false);
        setStatus('error');
        setMessage('Impossible de charger votre profil.');
      }
    };

    loadUser();

    return () => controller.abort();
  }, []);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStatus('loading');
    setMessage('');

    if (!firstName.trim() || !lastName.trim() || !email.trim()) {
      setStatus('error');
      setMessage('Veuillez renseigner votre nom, prenom et email.');
      return;
    }

    if ((password || confirmPassword) && !currentPassword) {
      setStatus('error');
      setMessage("Veuillez renseigner l'ancien mot de passe.");
      return;
    }

    if ((password || confirmPassword) && password !== confirmPassword) {
      setStatus('error');
      setMessage('Les mots de passe ne correspondent pas.');
      return;
    }

    if (currentPassword && !password && !confirmPassword) {
      setStatus('error');
      setMessage('Veuillez renseigner le nouveau mot de passe.');
      return;
    }

    const token = getAccessToken();
    if (!token) {
      setStatus('error');
      setMessage('Token manquant ou session expiree. Connectez-vous.');
      return;
    }

    try {
      await updateCurrentUser(token, {
        first_name: firstName.trim(),
        last_name: lastName.trim(),
        email: email.trim(),
        current_password: password ? currentPassword : undefined,
        password: password ? password : undefined,
      });
      setStatus('success');
      setMessage('Profil mis a jour.');
      setCurrentPassword('');
      setPassword('');
      setConfirmPassword('');
    } catch (error) {
      setStatus('error');
      if (error instanceof ApiError) {
        if (error.status === 401) {
          setMessage('Session invalide ou expiree. Reconnectez-vous.');
        } else if (error.status === 400) {
          setMessage(error.message);
        } else {
          setMessage('Mise a jour impossible.');
        }
      } else {
        setMessage('Mise a jour impossible.');
      }
    }
  };

  return (
    <main className="mt-8 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
      <div className="mx-auto w-full max-w-3xl">
        <Card className="border-border/70 bg-background/70 shadow-soft">
          <CardHeader className="space-y-2">
            <CardTitle>Modification utilisateur</CardTitle>
            <CardDescription>
              Mettez a jour vos informations personnelles et votre mot de passe.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoadingUser ? (
              <div className="flex min-h-[220px] items-center justify-center">
                <Spinner size="lg" />
              </div>
            ) : (
              <form className="grid gap-4 sm:grid-cols-2" onSubmit={handleSubmit}>
                <div className="grid gap-2">
                  <Label htmlFor="settings-last-name">Nom</Label>
                  <Input
                    id="settings-last-name"
                    placeholder="Ex: Dupont"
                    value={lastName}
                    onChange={(event) => setLastName(event.target.value)}
                    disabled={status === 'loading'}
                  />
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="settings-first-name">Prenom</Label>
                  <Input
                    id="settings-first-name"
                    placeholder="Ex: Amina"
                    value={firstName}
                    onChange={(event) => setFirstName(event.target.value)}
                    disabled={status === 'loading'}
                  />
                </div>

                <div className="grid gap-2 sm:col-span-2">
                  <Label htmlFor="settings-email">Email</Label>
                  <Input
                    id="settings-email"
                    type="email"
                    placeholder="nom@entreprise.com"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    disabled={status === 'loading'}
                  />
                </div>

                <div className="grid gap-2 sm:col-span-2">
                  <Label htmlFor="settings-current-password">Ancien mot de passe</Label>
                  <Input
                    id="settings-current-password"
                    type="password"
                    placeholder="Votre mot de passe actuel"
                    value={currentPassword}
                    onChange={(event) => setCurrentPassword(event.target.value)}
                    disabled={status === 'loading'}
                  />
                </div>

                <div className="grid gap-2 sm:col-span-2">
                  <Label htmlFor="settings-password">Nouveau mot de passe</Label>
                  <Input
                    id="settings-password"
                    type="password"
                    placeholder="Laissez vide pour ne pas changer"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    disabled={status === 'loading'}
                  />
                </div>

                <div className="grid gap-2 sm:col-span-2">
                  <Label htmlFor="settings-confirm-password">Confirmer le mot de passe</Label>
                  <Input
                    id="settings-confirm-password"
                    type="password"
                    placeholder="Repetez le mot de passe"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    disabled={status === 'loading'}
                  />
                </div>

                {status !== 'idle' && message ? (
                  <div className="sm:col-span-2">
                    <Alert variant={status === 'error' ? 'destructive' : 'default'}>
                      <AlertTitle>
                        {status === 'error' ? 'Mise a jour impossible' : 'Profil mis a jour'}
                      </AlertTitle>
                      <AlertDescription>{message}</AlertDescription>
                    </Alert>
                  </div>
                ) : null}

                <div className="sm:col-span-2 flex justify-end">
                  <Button type="submit" isLoading={status === 'loading'}>
                    Enregistrer les modifications
                  </Button>
                </div>
              </form>
            )}
          </CardContent>
          <CardFooter className="text-xs text-muted-foreground">
            Vos informations sont utilisees uniquement pour votre compte SGCI.
          </CardFooter>
        </Card>
      </div>
    </main>
  );
}
