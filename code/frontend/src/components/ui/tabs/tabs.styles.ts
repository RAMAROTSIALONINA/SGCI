import { cva } from 'class-variance-authority';

export const tabsListStyles = cva(
  'relative isolate inline-flex items-center justify-center gap-1 overflow-hidden rounded-2xl border border-border/70 bg-surface-muted p-1 text-muted-foreground shadow-soft before:pointer-events-none before:absolute before:inset-y-1 before:left-0 before:z-0 before:rounded-full before:border before:border-primary/45 before:bg-transparent before:backdrop-blur-sm before:shadow-[0_0_0_1px_hsl(var(--primary)_/_0.15),0_12px_24px_-18px_hsl(var(--primary)_/_0.55)] before:ring-1 before:ring-white/25 before:opacity-[var(--tabs-indicator-opacity)] before:transition-[transform,width,opacity] before:duration-[420ms] before:ease-[cubic-bezier(0.2,1.1,0.3,1)] before:translate-x-[var(--tabs-indicator-x)] before:w-[var(--tabs-indicator-w)] before:will-change-[transform,width] after:pointer-events-none after:absolute after:inset-y-2 after:left-0 after:z-0 after:rounded-full after:border after:border-primary/25 after:bg-transparent after:opacity-[var(--tabs-indicator-opacity)] after:blur-sm after:transition-[transform,width,opacity] after:duration-[600ms] after:ease-out after:translate-x-[calc(var(--tabs-indicator-x)-18px)] after:w-[calc(var(--tabs-indicator-w)+36px)]',
  {
    variants: {
      size: {
        sm: 'h-9',
        md: 'h-10',
        lg: 'h-12',
      },
    },
    defaultVariants: {
      size: 'md',
    },
  },
);

export const tabsTriggerStyles = cva(
  'relative z-10 inline-flex items-center justify-center whitespace-nowrap rounded-xl px-3 py-1 text-sm font-semibold transition-colors duration-150 ease-[var(--transition-smooth)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50 data-[state=active]:text-foreground',
  {
    variants: {
      size: {
        sm: 'h-7 text-xs',
        md: 'h-8',
        lg: 'h-10 text-base px-4',
      },
    },
    defaultVariants: {
      size: 'md',
    },
  },
);

export const tabsContentStyles = cva(
  'mt-3 rounded-2xl border border-border/70 bg-surface p-4 text-sm shadow-soft focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
);
