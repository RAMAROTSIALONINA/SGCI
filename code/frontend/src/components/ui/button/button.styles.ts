import { cva } from 'class-variance-authority';

export const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 rounded-lg font-semibold leading-5 tracking-tight transition-all duration-200 ease-[var(--transition-smooth)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-65',
  {
    variants: {
      variant: {
        default:
          'bg-primary text-primary-foreground shadow-soft hover:shadow-soft-lg hover:bg-primary/92 active:translate-y-[1px]',
        secondary:
          'bg-secondary text-secondary-foreground shadow-soft hover:bg-secondary/80 hover:shadow-soft-lg active:translate-y-[1px]',
        destructive:
          'bg-destructive text-destructive-foreground shadow-soft hover:bg-destructive/90 hover:shadow-soft-lg active:translate-y-[1px]',
        outline:
          'border border-border/70 bg-surface text-foreground shadow-soft hover:border-border hover:bg-surface-muted/80 hover:shadow-soft-lg active:translate-y-[1px]',
        ghost:
          'bg-transparent text-foreground hover:bg-accent/60 hover:text-accent-foreground active:bg-accent/80',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        sm: 'h-9 rounded-md px-3 text-xs [&>svg]:size-4',
        default: 'h-10 px-4 text-sm [&>svg]:size-4',
        lg: 'h-11 rounded-xl px-5 text-base [&>svg]:size-5',
        icon: 'h-10 w-10 [&>svg]:size-5',
      },
      loading: {
        true: 'cursor-wait opacity-80',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
);
