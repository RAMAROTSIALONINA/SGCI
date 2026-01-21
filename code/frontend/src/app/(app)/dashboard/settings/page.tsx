import { PageHeader } from '@/components';

export default function SettingsPage() {
  return (
    <>
      <PageHeader
        title="Settings"
        description="Configurez les preferences et les parametres globaux."
      />

      <main className="mt-8 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
        <div
          className="h-full min-h-[360px]"
          aria-label="Settings empty content area"
        />
      </main>
    </>
  );
}
