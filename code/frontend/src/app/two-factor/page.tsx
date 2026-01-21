import { AmbientBackground, TwoFactorCard } from '@/components';

export default function TwoFactorPage() {
  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <AmbientBackground />

      <main className="mx-auto flex min-h-screen items-center justify-center px-6 py-16 sm:px-10">
        <div className="flex w-full max-w-6xl items-center justify-center">
          <TwoFactorCard />
        </div>
      </main>
    </div>
  );
}
