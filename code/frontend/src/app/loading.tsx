import { AmbientBackground, Badge, Spinner } from '@/components';
export default function Loading() {
  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-6 py-16">
      <AmbientBackground />
      <div className="w-full max-w-2xl rounded-3xl border border-border/70 bg-card/80 p-8 shadow-soft-lg backdrop-blur">
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <Badge variant="secondary">Chargement</Badge>
            <h1 className="text-2xl font-semibold text-foreground">Preparation de votre espace</h1>
            <p className="text-sm text-muted-foreground">
              Nous recuperons les donnees et les permissions en cours.
            </p>
          </div>
          <Spinner size="lg" className="text-primary" />
        </div>
        <div className="mt-8 space-y-3">
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted/60">
            <div className="h-full w-1/2 animate-pulse rounded-full bg-primary/70" />
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="h-10 rounded-2xl bg-muted/40" />
            <div className="h-10 rounded-2xl bg-muted/40" />
            <div className="h-10 rounded-2xl bg-muted/40" />
            <div className="h-10 rounded-2xl bg-muted/40" />
          </div>
        </div>
      </div>
    </main>
  );
}
