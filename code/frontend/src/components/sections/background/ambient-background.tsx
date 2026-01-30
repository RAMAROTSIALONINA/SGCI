export function AmbientBackground() {
  return (
    <div className="pointer-events-none absolute inset-0 -z-10" aria-hidden="true">
      <div className="absolute -left-24 top-24 h-72 w-72 rounded-full bg-[radial-gradient(circle,_rgba(var(--palette-primary-rgb)_/_0.28),_transparent_70%)] blur-3xl" />
      <div className="absolute right-[-80px] top-[-60px] h-72 w-72 rounded-full bg-[radial-gradient(circle,_rgba(var(--palette-accent-rgb)_/_0.32),_transparent_70%)] blur-3xl" />
      <div className="absolute inset-0 bg-[linear-gradient(120deg,_rgba(11,42,42,0.04),_transparent_40%,_rgba(11,42,42,0.06))]" />
    </div>
  );
}
