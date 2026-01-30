import { cva } from 'class-variance-authority';

export const labelStyles = cva(
  'text-sm font-medium leading-none text-foreground/80 transition-colors peer-disabled:cursor-not-allowed peer-disabled:opacity-60',
  {
    variants: {
      size: {
        sm: 'text-xs',
        md: 'text-sm',
        lg: 'text-base',
      },
      tone: {
        default: '',
        muted: 'text-muted-foreground',
      },
    },
    defaultVariants: {
      size: 'md',
      tone: 'default',
    },
  },
);
