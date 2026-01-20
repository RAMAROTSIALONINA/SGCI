import { cva } from 'class-variance-authority';

export const switchRootStyles = cva(
  'inline-flex shrink-0 cursor-pointer items-center rounded-full border border-border/70 bg-input shadow-soft transition-all duration-200 ease-[var(--transition-smooth)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-primary',
  {
    variants: {
      size: {
        sm: 'h-5 w-9',
        md: 'h-6 w-11',
        lg: 'h-7 w-12',
      },
    },
    defaultVariants: {
      size: 'md',
    },
  },
);

export const switchThumbStyles = cva(
  'pointer-events-none block rounded-full bg-surface shadow-soft transition-transform duration-200 ease-[var(--transition-smooth)] data-[state=checked]:translate-x-[calc(100%-2px)] data-[state=unchecked]:translate-x-0',
  {
    variants: {
      size: {
        sm: 'h-4 w-4 translate-x-[2px]',
        md: 'h-5 w-5 translate-x-[2px]',
        lg: 'h-6 w-6 translate-x-[2px]',
      },
    },
    defaultVariants: {
      size: 'md',
    },
  },
);
