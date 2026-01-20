import { cva } from 'class-variance-authority';

export const textareaStyles = cva(
  'flex min-h-[110px] w-full rounded-xl border border-border/80 bg-surface px-3 py-3 text-sm font-medium text-foreground shadow-soft transition-all duration-200 ease-[var(--transition-smooth)] placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60',
  {
    variants: {
      tone: {
        default: '',
        error: 'border-destructive/70 focus-visible:ring-destructive/60',
      },
    },
    defaultVariants: {
      tone: 'default',
    },
  },
);
