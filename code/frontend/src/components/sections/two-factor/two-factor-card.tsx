'use client';

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

const MAX_ATTEMPTS = 3;

export function TwoFactorCard() {
  const [code, setCode] = React.useState('');
  const [attempts, setAttempts] = React.useState(0);
  const [feedback, setFeedback] = React.useState<'idle' | 'error' | 'resent'>(
    'idle',
  );

  const isLocked = attempts >= MAX_ATTEMPTS;

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isLocked) {
      return;
    }

    const sanitized = code.replace(/\s/g, '');
    if (!sanitized) {
      setFeedback('error');
      return;
    }

    setAttempts((prev) => Math.min(prev + 1, MAX_ATTEMPTS));
    setFeedback('error');
  };

  const handleResend = () => {
    setFeedback('resent');
  };

  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const digitsOnly = event.target.value.replace(/\D/g, '');
    setCode(digitsOnly);
    if (feedback !== 'idle') {
      setFeedback('idle');
    }
  };

  return (
    <Card
      padding="none"
      className="w-full max-w-4xl overflow-hidden border-border/70 bg-card/90 shadow-soft-lg backdrop-blur"
    >
      <div className="grid gap-0 lg:grid-cols-[1.15fr_1fr]">
        <div className="relative flex flex-col justify-between gap-6 border-b border-border/70 bg-surface-muted/70 p-8 lg:border-b-0 lg:border-r">
          <div
            className="pointer-events-none absolute inset-0 -z-10"
            aria-hidden="true"
          >
            <div className="absolute -left-16 top-10 h-40 w-40 rounded-full bg-[radial-gradient(circle,_rgba(35,83,71,0.22),_transparent_70%)] blur-3xl" />
            <div className="absolute bottom-6 right-6 h-28 w-28 rounded-full bg-[radial-gradient(circle,_rgba(142,182,155,0.25),_transparent_70%)] blur-2xl" />
            <div className="absolute inset-0 bg-[linear-gradient(140deg,_rgba(5,31,32,0.06),_transparent_55%)]" />
          </div>

          <div className="relative space-y-3">
            <div className="text-xs font-semibold tracking-[0.35em] text-muted-foreground">
              SGCI
            </div>
            <h2 className="text-2xl font-semibold text-foreground">
              Verification 2FA
            </h2>
            <p className="text-sm text-muted-foreground">
              L&apos;administrateur qui vous a cree recoit le code. Demandez-le
              pour confirmer votre connexion.
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
                  <span>Recevez le code a usage unique de l&apos;admin.</span>
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
            <CardTitle className="text-xl font-semibold">
              Saisir le code
            </CardTitle>
            <CardDescription>
              Entrez le code recu par l&apos;administrateur pour continuer.
            </CardDescription>
          </CardHeader>

          <CardContent className="mt-4">
            <form className="space-y-4" onSubmit={handleSubmit}>
              <div className="grid gap-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Label htmlFor="twofa-code">Code de verification</Label>
                  <Badge variant={isLocked ? 'destructive' : 'muted'}>
                    Tentatives faites: {attempts}/{MAX_ATTEMPTS}
                  </Badge>
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
                  disabled={isLocked}
                  tone={isLocked || feedback === 'error' ? 'error' : 'default'}
                />
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <Button
                  type="submit"
                  size="lg"
                  className="w-full sm:flex-1"
                  disabled={isLocked}
                >
                  Verifier le code
                </Button>
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  className="self-start px-0 sm:self-center"
                  onClick={handleResend}
                >
                  Reenvoyer
                </Button>
              </div>

              {isLocked ? (
                <Alert variant="destructive">
                  <AlertTitle>Saisie bloquee</AlertTitle>
                  <AlertDescription>
                    Trop de tentatives. Contactez l&apos;administrateur pour
                    debloquer l&apos;acces.
                  </AlertDescription>
                </Alert>
              ) : feedback === 'error' ? (
                <Alert variant="destructive">
                  <AlertTitle>Code invalide</AlertTitle>
                  <AlertDescription>
                    Le code saisi est incorrect. Verifiez aupres de
                    l&apos;administrateur.
                  </AlertDescription>
                </Alert>
              ) : feedback === 'resent' ? (
                <Alert>
                  <AlertTitle>Code renvoye</AlertTitle>
                  <AlertDescription>
                    Un nouveau code a ete envoye a l&apos;administrateur.
                  </AlertDescription>
                </Alert>
              ) : null}
            </form>
          </CardContent>
        </div>
      </div>
    </Card>
  );
}
