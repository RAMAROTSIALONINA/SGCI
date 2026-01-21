import { PageHeader } from '@/components';

export default function DashboardPage() {
  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Vue d'ensemble de votre activite et des indicateurs SGCI."
      />

      <main className="mt-8 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
        <div
          className="h-full min-h-[360px]"
          aria-label="Dashboard empty content area"
        />
      </main>
    </>
  );
}
