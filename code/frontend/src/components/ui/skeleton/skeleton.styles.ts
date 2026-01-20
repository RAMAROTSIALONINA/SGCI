import { cva } from 'class-variance-authority';

export const skeletonStyles = cva(
  'animate-pulse rounded-2xl bg-muted/70 shadow-soft',
  {
    variants: {
      size: {
        sm: 'h-4',
        md: 'h-6',
        lg: 'h-10',
      },
    },
  },
);
