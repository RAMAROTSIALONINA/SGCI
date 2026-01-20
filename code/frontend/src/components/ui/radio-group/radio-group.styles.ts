import { cva } from 'class-variance-authority';

export const radioGroupStyles = cva('grid gap-2');

export const radioItemStyles = cva(
  'aspect-square rounded-full border border-border/80 bg-surface text-primary shadow-soft transition-all duration-150 ease-[var(--transition-smooth)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-primary data-[state=checked]:bg-primary/10',
  {
    variants: {
      size: {
        sm: 'h-4 w-4',
        md: 'h-5 w-5',
        lg: 'h-6 w-6',
      },
    },
    defaultVariants: {
      size: 'md',
    },
  },
);
