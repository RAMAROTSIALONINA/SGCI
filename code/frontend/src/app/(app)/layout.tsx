import { DashboardSidebar } from '@/app/layout/navbar';

export default function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_15%_20%,_rgba(35,83,71,0.22),_transparent_55%)]" />
        <div className="absolute -right-32 top-8 h-72 w-72 rounded-full bg-[radial-gradient(circle,_rgba(142,182,155,0.35),_transparent_70%)] blur-3xl" />
        <div className="absolute inset-0 bg-[linear-gradient(120deg,_rgba(5,31,32,0.03),_transparent_45%,_rgba(5,31,32,0.08))]" />
        <div className="absolute inset-0 bg-[linear-gradient(transparent_0,_transparent_47px,_rgba(35,83,71,0.06)_48px),linear-gradient(90deg,_transparent_0,_transparent_47px,_rgba(35,83,71,0.06)_48px)] bg-[size:48px_48px]" />
      </div>

      <div className="relative min-h-screen">
        <DashboardSidebar className="peer fixed left-0 top-0 z-20 h-screen rounded-none rounded-r-3xl border-l-0" />

        <div className="flex min-h-screen flex-1 flex-col py-10 pl-24 pr-6 transition-[padding] duration-300 ease-[var(--transition-smooth)] peer-hover:pl-[19rem] sm:pr-10">
          {children}
        </div>
      </div>
    </div>
  );
}
