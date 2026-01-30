import Link from 'next/link';

import { AmbientBackground, buttonVariants } from '@/components';
export default function NotFound() {
  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-6 py-16">
      <AmbientBackground />
      <div className="w-full max-w-xl rounded-3xl border border-border/70 bg-card/80 p-8 text-center shadow-soft-lg backdrop-blur">
        <div className="text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
          SGCI
        </div>
        <h1 className="mt-3 text-5xl font-semibold text-foreground">404</h1>
        <p className="mt-3 text-sm text-muted-foreground">
          La page demandee est introuvable ou n&apos;existe plus.
        </p>
        <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
          <Link href="/" className={buttonVariants({ size: 'lg' })}>
            Retour a l&apos;accueil
          </Link>
          <Link href="/dashboard" className={buttonVariants({ size: 'lg', variant: 'ghost' })}>
            Aller au tableau de bord
          </Link>
        </div>
      </div>
    </main>
  );
}
