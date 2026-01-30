import { cva } from 'class-variance-authority';

export const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs font-semibold tracking-tight transition-all duration-150 ease-[var(--transition-smooth)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
  {
    variants: {
      variant: {
        default:
          'border-transparent bg-primary/90 text-primary-foreground shadow-soft hover:bg-primary',
        secondary:
          'border-transparent bg-secondary text-secondary-foreground shadow-soft hover:bg-secondary/80',
        muted: 'border border-border/70 bg-surface-muted text-foreground/80 hover:border-border',
        destructive:
          'border-transparent bg-destructive text-destructive-foreground shadow-soft hover:bg-destructive/90',
        outline: 'border border-border/70 bg-transparent text-foreground hover:border-border',
      },
      tone: {
        success:
          'bg-[color:rgb(var(--palette-primary-rgb)_/_0.18)] !text-foreground dark:bg-[color:rgb(var(--palette-primary-rgb)_/_0.28)] dark:!text-foreground',
        info: 'bg-[color:rgb(var(--palette-accent-rgb)_/_0.18)] !text-foreground dark:bg-[color:rgb(var(--palette-accent-rgb)_/_0.28)] dark:!text-foreground',
        warning:
          'bg-[color:rgb(var(--palette-secondary-rgb)_/_0.2)] !text-foreground dark:bg-[color:rgb(var(--palette-secondary-rgb)_/_0.3)] dark:!text-foreground',
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
