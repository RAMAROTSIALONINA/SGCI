export const navbarStyles = {
  container:
    'flex h-full flex-col gap-6 rounded-3xl border border-border bg-[linear-gradient(180deg,_rgba(var(--palette-primary-rgb)_/_0.16),_rgba(var(--palette-accent-rgb)_/_0.06))] py-6 shadow-soft-lg backdrop-blur transition-[width,padding] duration-300 ease-[var(--transition-smooth)]',
  containerExpanded: 'w-72 px-6',
  containerCollapsed: 'w-20 px-4',
  header: 'flex items-center justify-between gap-4',
  brand: 'flex items-center gap-3',
  brandBadge: 'flex h-10 w-10 items-center justify-center overflow-hidden',
  brandLogo: 'h-10 w-10 object-contain',
  brandFallback: 'text-xs font-semibold tracking-[0.2em] text-foreground',
  brandText:
    'overflow-hidden whitespace-nowrap text-sm font-semibold transition-all duration-300 ease-[var(--transition-smooth)]',
  brandTextExpanded: 'translate-x-0 max-w-[160px] opacity-100',
  brandTextCollapsed: '-translate-x-2 max-w-0 opacity-0',
  statusDot: 'h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.7)]',
  user: 'flex items-center gap-2 px-3',
  userLabel:
    'overflow-hidden whitespace-nowrap text-[0.65rem] uppercase tracking-[0.2em] text-muted-foreground/70 transition-all duration-300 ease-[var(--transition-smooth)]',
  userLabelExpanded: 'translate-x-0 max-w-[80px] opacity-100',
  userLabelCollapsed: '-translate-x-2 max-w-0 opacity-0',
  userName:
    'overflow-hidden whitespace-nowrap text-sm font-semibold transition-all duration-300 ease-[var(--transition-smooth)]',
  userNameExpanded: 'translate-x-0 max-w-[140px] opacity-100',
  userNameCollapsed: '-translate-x-2 max-w-0 opacity-0',
  nav: 'space-y-2 text-sm',
  linkBase:
    'group flex items-center rounded-2xl border border-transparent px-3 py-2 transition-all outline-none focus:outline-none focus-visible:outline-none focus:ring-0 focus-visible:ring-0 focus:ring-offset-0 focus-visible:ring-offset-0',
  linkActive:
    'border border-border/70 bg-[linear-gradient(135deg,_rgba(var(--palette-primary-rgb)_/_0.18),_rgba(var(--palette-accent-rgb)_/_0.08))] text-foreground shadow-soft',
  linkInactive:
    'text-muted-foreground hover:border-border/60 hover:bg-[rgba(var(--palette-primary-rgb)_/_0.08)] hover:text-foreground hover:shadow-soft',
  iconBase: 'flex h-9 w-9 items-center justify-center rounded-xl transition-colors',
  iconActive: 'bg-transparent text-foreground',
  iconInactive:
    'bg-transparent text-muted-foreground group-hover:bg-transparent group-hover:text-foreground',
  label:
    'overflow-hidden whitespace-nowrap text-sm font-medium transition-all duration-300 ease-[var(--transition-smooth)]',
  labelExpanded: 'translate-x-0 max-w-[160px] opacity-100 pl-3',
  labelCollapsed: '-translate-x-2 max-w-0 opacity-0 pl-0',
  secondaryWrapper: 'mt-auto space-y-2 text-sm',
  secondaryLink:
    'group flex items-center rounded-2xl border border-transparent px-3 py-2 text-muted-foreground transition-all hover:border-border/60 hover:bg-[rgba(var(--palette-primary-rgb)_/_0.08)] hover:text-foreground hover:shadow-soft outline-none focus:outline-none focus-visible:outline-none focus:ring-0 focus-visible:ring-0 focus:ring-offset-0 focus-visible:ring-offset-0',
  secondaryIcon:
    'relative flex h-9 w-9 items-center justify-center rounded-xl bg-transparent text-muted-foreground transition-colors group-hover:bg-transparent group-hover:text-foreground',
  notificationCount:
    'absolute -top-1 -right-1 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-destructive px-1 text-[0.6rem] font-semibold text-destructive-foreground shadow-soft',
};
