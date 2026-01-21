export const miniMenuStyles = {
  container: 'flex w-full items-center justify-center gap-12',
  buttonBase:
    'h-8 min-w-[140px] rounded-full border px-4 text-xs font-semibold tracking-tight transition-all duration-200 ease-[var(--transition-smooth)] active:translate-y-[1px]',
  buttonActive:
    'border-border bg-primary/90 text-primary-foreground shadow-soft-lg ring-1 ring-primary/40',
  buttonInactive:
    'border-border/80 bg-background/40 text-muted-foreground ring-1 ring-transparent hover:border-border hover:bg-background/70 hover:text-foreground hover:shadow-soft hover:ring-border/60',
};
