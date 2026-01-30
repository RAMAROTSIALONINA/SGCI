'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import * as React from 'react';

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
} from '@/components/ui';
import { ApiError, resendOtp, verifyOtp } from '@/lib/api';
import { setAuthTokens } from '@/lib/auth/tokens';

const MAX_ATTEMPTS = 5;
const OTP_TTL_SECONDS = 5 * 60;
const OTP_STORAGE_KEY = 'sgci_pending_otp_at';

const formatRemaining = (seconds: number) => {
  const clamped = Math.max(0, seconds);
  const minutes = Math.floor(clamped / 60);
  const secs = clamped % 60;
  return `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
};

export function TwoFactorCard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = React.useState('');
  const [code, setCode] = React.useState('');
  const [attempts, setAttempts] = React.useState(0);
  const [expiresAt, setExpiresAt] = React.useState<number | null>(null);
  const [remainingSeconds, setRemainingSeconds] = React.useState(OTP_TTL_SECONDS);
  const [feedback, setFeedback] = React.useState<'idle' | 'error' | 'resent' | 'success'>('idle');
  const [errorMessage, setErrorMessage] = React.useState('');
  const [isLoading, setIsLoading] = React.useState(false);

  const isLocked = attempts >= MAX_ATTEMPTS;
  const isExpired = remainingSeconds <= 0;

  const initExpiry = React.useCallback((forceReset = false) => {
    if (typeof window === 'undefined') {
      return;
    }
    const stored = localStorage.getItem(OTP_STORAGE_KEY);
    let issuedAt = stored ? Number(stored) : Number.NaN;
    if (!Number.isFinite(issuedAt) || forceReset) {
      issuedAt = Date.now();
      localStorage.setItem(OTP_STORAGE_KEY, String(issuedAt));
    }
    setExpiresAt(issuedAt + OTP_TTL_SECONDS * 1000);
  }, []);

  React.useEffect(() => {
    const emailFromQuery = searchParams.get('email');
    if (emailFromQuery) {
      setEmail(emailFromQuery);
      return;
    }

    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('sgci_pending_email');
      if (stored) {
        setEmail(stored);
      }
    }
  }, [searchParams]);

  React.useEffect(() => {
    initExpiry();
  }, [initExpiry]);

  React.useEffect(() => {
    if (!expiresAt) {
      return;
    }
    const updateRemaining = () => {
      const next = Math.ceil((expiresAt - Date.now()) / 1000);
      setRemainingSeconds(Math.max(0, next));
    };
    updateRemaining();
    const interval = window.setInterval(updateRemaining, 1000);
    return () => window.clearInterval(interval);
  }, [expiresAt]);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isLocked) {
      return;
    }

    const sanitized = code.replace(/\s/g, '');
    if (!email.trim()) {
      setErrorMessage('Email manquant. Revenez a la page de connexion.');
      setFeedback('error');
      return;
    }

    if (!sanitized) {
      setErrorMessage('Code manquant. Saisissez les 6 chiffres.');
      setFeedback('error');
      return;
    }

    setIsLoading(true);
    setErrorMessage('');

    try {
      const response = await verifyOtp({ email, code: sanitized });
      setAuthTokens({
        access_token: response.access_token,
        refresh_token: response.refresh_token,
      });
      if (typeof window !== 'undefined') {
        localStorage.removeItem('sgci_pending_email');
        localStorage.removeItem(OTP_STORAGE_KEY);
      }
      setFeedback('success');
      router.push('/dashboard');
    } catch {
      setAttempts((prev) => Math.min(prev + 1, MAX_ATTEMPTS));
      setFeedback('error');
      setErrorMessage('Code invalide ou expire.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    if (!email.trim()) {
      setErrorMessage('Email manquant. Revenez a la page de connexion.');
      setFeedback('error');
      return;
    }

    setIsLoading(true);
    setErrorMessage('');

    try {
      await resendOtp({ email });
      setFeedback('resent');
      initExpiry(true);
    } catch (resendError) {
      setFeedback('error');
      if (resendError instanceof ApiError) {
        setErrorMessage(resendError.message);
      } else {
        setErrorMessage('Impossible de renvoyer le code.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const digitsOnly = event.target.value.replace(/\D/g, '');
    setCode(digitsOnly);
    if (feedback !== 'idle') {
      setFeedback('idle');
      setErrorMessage('');
    }
  };

  return (
    <Card
      padding="none"
      className="w-full max-w-4xl overflow-hidden border-border/70 bg-card/90 shadow-soft-lg backdrop-blur"
    >
      <div className="grid gap-0 lg:grid-cols-[1.15fr_1fr]">
        <div className="relative flex flex-col justify-between gap-6 border-b border-border/70 bg-surface-muted/70 p-8 lg:border-b-0 lg:border-r">
          <div className="pointer-events-none absolute inset-0 -z-10" aria-hidden="true">
            <div className="absolute -left-16 top-10 h-40 w-40 rounded-full bg-[radial-gradient(circle,_rgba(var(--palette-primary-rgb)_/_0.24),_transparent_70%)] blur-3xl" />
            <div className="absolute bottom-6 right-6 h-28 w-28 rounded-full bg-[radial-gradient(circle,_rgba(var(--palette-accent-rgb)_/_0.3),_transparent_70%)] blur-2xl" />
            <div className="absolute inset-0 bg-[linear-gradient(140deg,_rgba(11,42,42,0.06),_transparent_55%)]" />
          </div>

          <div className="relative space-y-3">
            <div className="text-xs font-semibold tracking-[0.35em] text-muted-foreground">
              SGCI
            </div>
            <h2 className="text-2xl font-semibold text-foreground">Verification 2FA</h2>
            <p className="text-sm text-muted-foreground">
              Le code est envoye sur votre email. Consultez votre boite de reception pour confirmer
              votre connexion.
            </p>
          </div>

          <div className="relative space-y-4">
            <Badge variant="secondary">Acces securise</Badge>
            <div className="rounded-2xl border border-border/60 bg-background/70 p-4 text-sm text-muted-foreground shadow-soft">
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-foreground/70">
                Etapes
              </div>
              <ul className="mt-3 space-y-2">
                <li className="flex items-start gap-2">
                  <span className="mt-2 h-1.5 w-1.5 rounded-full bg-primary/80" />
                  <span>Recevez le code a usage unique par email.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="mt-2 h-1.5 w-1.5 rounded-full bg-primary/80" />
                  <span>Saisissez les 6 chiffres pour valider l&apos;acces.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="mt-2 h-1.5 w-1.5 rounded-full bg-primary/80" />
                  <span>Blocage automatique apres plusieurs erreurs.</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div className="p-8">
          <CardHeader className="space-y-2 text-left">
            <CardTitle className="text-xl font-semibold">Saisir le code</CardTitle>
            <CardDescription>Entrez le code recu par email pour continuer.</CardDescription>
          </CardHeader>

          <CardContent className="mt-4">
            <form className="space-y-4" onSubmit={handleSubmit}>
              <div className="grid gap-2">
                <Label htmlFor="twofa-email">Email</Label>
                <Input
                  id="twofa-email"
                  type="email"
                  placeholder="votre@email.com"
                  autoComplete="email"
                  size="lg"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="grid gap-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Label htmlFor="twofa-code">Code de verification</Label>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={isLocked ? 'destructive' : 'muted'}>
                      Tentatives faites: {attempts}/{MAX_ATTEMPTS}
                    </Badge>
                    <Badge variant={isExpired ? 'destructive' : 'secondary'}>
                      Expire dans: {formatRemaining(remainingSeconds)}
                    </Badge>
                  </div>
                </div>
                <Input
                  id="twofa-code"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  size="lg"
                  maxLength={6}
                  value={code}
                  onChange={handleChange}
                  disabled={isLocked || isLoading}
                  tone={isLocked || feedback === 'error' ? 'error' : 'default'}
                />
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <Button
                  type="submit"
                  size="lg"
                  className="w-full sm:flex-1"
                  disabled={isLocked}
                  isLoading={isLoading}
                >
                  Verifier le code
                </Button>
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  className="self-start px-0 sm:self-center"
                  onClick={handleResend}
                  disabled={isLoading}
                >
                  Reenvoyer
                </Button>
              </div>

              {isLocked ? (
                <Alert variant="destructive">
                  <AlertTitle>Saisie bloquee</AlertTitle>
                  <AlertDescription>
                    Trop de tentatives. Demandez un nouveau code pour continuer.
                  </AlertDescription>
                </Alert>
              ) : feedback === 'error' ? (
                <Alert variant="destructive">
                  <AlertTitle>Code invalide</AlertTitle>
                  <AlertDescription>
                    {errorMessage ||
                      'Le code saisi est incorrect. Verifiez le code recu par email.'}
                  </AlertDescription>
                </Alert>
              ) : feedback === 'resent' ? (
                <Alert>
                  <AlertTitle>Code renvoye</AlertTitle>
                  <AlertDescription>Un nouveau code a ete envoye par email.</AlertDescription>
                </Alert>
              ) : feedback === 'success' ? (
                <Alert>
                  <AlertTitle>Connexion reussie</AlertTitle>
                  <AlertDescription>Vous etes connecte. Redirection en cours.</AlertDescription>
                </Alert>
              ) : null}
            </form>
          </CardContent>
        </div>
      </div>
    </Card>
  );
}
