'use client';

import Image from 'next/image';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
} from '@/components/ui';
import { login } from '@/lib/api';
import { setAuthTokens } from '@/lib/auth/tokens';

export function LoginCard() {
  const router = useRouter();
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [status, setStatus] = React.useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = React.useState('');

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStatus('loading');
    setMessage('');

    try {
      const response = await login({ email, password });

      if (response.access_token && response.refresh_token) {
        setAuthTokens({
          access_token: response.access_token,
          refresh_token: response.refresh_token,
        });
        setStatus('success');
        setMessage('Connexion reussie.');
        router.push('/dashboard');
        return;
      }

      if (response.message) {
        if (typeof window !== 'undefined') {
          localStorage.setItem('sgci_pending_email', email);
          localStorage.setItem('sgci_pending_otp_at', String(Date.now()));
        }
        setStatus('success');
        setMessage(response.message);
        router.push('/two-factor');
        return;
      }

      setStatus('error');
      setMessage('Reponse inattendue du serveur.');
    } catch {
      setStatus('error');
      setMessage('Identifiants invalides ou service indisponible.');
    }
  };

  return (
    <Card className="w-full max-w-md border-border/70 bg-card/90 shadow-soft-lg backdrop-blur">
      <CardHeader className="space-y-2 text-center">
        <div className="flex justify-center">
          <Image
            src="/brand/logo_swis.png"
            alt="SGCI"
            width={64}
            height={64}
            className="h-16 w-16"
            priority
          />
        </div>
        <CardTitle className="text-2xl font-semibold">Se connecter</CardTitle>
        <CardDescription />
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={handleSubmit}>
          <div className="grid gap-2">
            <Label htmlFor="login-email">Email</Label>
            <Input
              id="login-email"
              type="email"
              placeholder="awa@entreprise.com"
              autoComplete="email"
              size="lg"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </div>

          <div className="grid gap-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="login-password">Mot de passe</Label>
              <Button variant="link" size="sm" type="button" className="px-0">
                Mot de passe oublie
              </Button>
            </div>
            <Input
              id="login-password"
              type="password"
              placeholder="Votre mot de passe"
              autoComplete="current-password"
              size="lg"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>

          <Button type="submit" size="lg" className="w-full" isLoading={status === 'loading'}>
            Se connecter
          </Button>
        </form>

        {status !== 'idle' && message ? (
          <Alert className="mt-4" variant={status === 'error' ? 'destructive' : 'default'}>
            <AlertTitle>
              {status === 'error' ? 'Connexion echouee' : 'Connexion en cours'}
            </AlertTitle>
            <AlertDescription>{message}</AlertDescription>
          </Alert>
        ) : null}
      </CardContent>
    </Card>
  );
}
