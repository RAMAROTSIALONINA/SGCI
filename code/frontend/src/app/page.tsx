import { AmbientBackground, HealthStatus, LoginCard } from '@/components';
export default function Page() {
  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <AmbientBackground />
      <main className="mx-auto flex min-h-screen items-center justify-center px-6 py-16 sm:px-10">
        <div className="flex w-full max-w-4xl flex-col items-center justify-center gap-6">
          <LoginCard />
          <HealthStatus />
        </div>
      </main>
    </div>
  );
}
