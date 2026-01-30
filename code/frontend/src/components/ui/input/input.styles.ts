import { cva } from 'class-variance-authority';

export const inputStyles = cva(
  'flex w-full rounded-xl border border-border/80 bg-surface px-3 text-sm font-medium text-foreground shadow-soft transition-all duration-200 ease-[var(--transition-smooth)] placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60',
  {
    variants: {
      size: {
        sm: 'h-9 text-xs',
        md: 'h-11',
        lg: 'h-12 text-base px-4',
      },
      tone: {
        default: '',
        error: 'border-destructive/70 focus-visible:ring-destructive/60',
      },
    },
    defaultVariants: {
      size: 'md',
      tone: 'default',
    },
  },
);
