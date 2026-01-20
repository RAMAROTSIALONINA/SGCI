import { cva } from 'class-variance-authority';

export const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs font-semibold tracking-tight transition-all duration-150 ease-[var(--transition-smooth)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary/90 text-primary-foreground shadow-soft hover:bg-primary',
        secondary:
          'border-transparent bg-secondary text-secondary-foreground shadow-soft hover:bg-secondary/80',
        muted:
          'border border-border/70 bg-surface-muted text-foreground/80 hover:border-border',
        destructive:
          'border-transparent bg-destructive text-destructive-foreground shadow-soft hover:bg-destructive/90',
        outline:
          'border border-border/70 bg-transparent text-foreground hover:border-border',
      },
      tone: {
        success: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-100',
        info: 'bg-blue-100 text-blue-800 dark:bg-blue-500/15 dark:text-blue-100',
        warning: 'bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-50',
      },
    },
    compoundVariants: [
      {
        variant: ['default', 'secondary', 'muted', 'destructive', 'outline'],
        tone: 'success',
        className: 'border-transparent',
      },
      {
        variant: ['default', 'secondary', 'muted', 'destructive', 'outline'],
        tone: 'info',
        className: 'border-transparent',
      },
      {
        variant: ['default', 'secondary', 'muted', 'destructive', 'outline'],
        tone: 'warning',
        className: 'border-transparent',
      },
    ],
    defaultVariants: {
      variant: 'default',
    },
  },
);
