export const navbarStyles = {
  container:
    'flex h-full flex-col gap-6 rounded-3xl border border-border bg-surface/85 py-6 shadow-soft backdrop-blur transition-[width,padding] duration-300 ease-[var(--transition-smooth)]',
  containerExpanded: 'w-72 px-6',
  containerCollapsed: 'w-20 px-4',
  header: 'flex items-center justify-between gap-4',
  brand: 'flex items-center gap-3',
  brandBadge:
    'flex h-10 w-10 items-center justify-center rounded-2xl border border-border/70 bg-background/70 text-xs font-semibold tracking-[0.2em] text-foreground',
  brandText:
    'overflow-hidden whitespace-nowrap text-sm font-semibold transition-all duration-300 ease-[var(--transition-smooth)]',
  brandTextExpanded: 'translate-x-0 max-w-[160px] opacity-100',
  brandTextCollapsed: '-translate-x-2 max-w-0 opacity-0',
  statusDot:
    'h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.7)]',
  nav: 'space-y-2 text-sm',
  linkBase:
    'group flex items-center rounded-2xl border border-transparent px-3 py-2 transition-colors outline-none focus:outline-none focus-visible:outline-none focus:ring-0 focus-visible:ring-0 focus:ring-offset-0 focus-visible:ring-offset-0',
  linkActive:
    'border border-border/80 bg-background/80 text-foreground shadow-soft',
  linkInactive:
    'text-muted-foreground hover:border-border/80 hover:bg-background/80 hover:text-foreground hover:shadow-soft',
  iconBase:
    'flex h-9 w-9 items-center justify-center rounded-xl border transition-colors',
  iconActive: 'border-border/70 bg-surface text-foreground',
  iconInactive:
    'border-transparent bg-background/40 text-muted-foreground group-hover:border-border/70 group-hover:bg-surface group-hover:text-foreground',
  label:
    'overflow-hidden whitespace-nowrap text-sm font-medium transition-all duration-300 ease-[var(--transition-smooth)]',
  labelExpanded: 'translate-x-0 max-w-[160px] opacity-100 pl-3',
  labelCollapsed: '-translate-x-2 max-w-0 opacity-0 pl-0',
  secondaryWrapper: 'mt-auto space-y-2 text-sm',
  secondaryLink:
    'group flex items-center rounded-2xl border border-transparent px-3 py-2 text-muted-foreground transition-colors hover:border-border/80 hover:bg-background/80 hover:text-foreground hover:shadow-soft outline-none focus:outline-none focus-visible:outline-none focus:ring-0 focus-visible:ring-0 focus:ring-offset-0 focus-visible:ring-offset-0',
  secondaryIcon:
    'flex h-9 w-9 items-center justify-center rounded-xl border border-transparent bg-background/40 text-muted-foreground transition-colors group-hover:border-border/70 group-hover:bg-surface group-hover:text-foreground',
};
