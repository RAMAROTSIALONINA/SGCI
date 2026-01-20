import { cva } from 'class-variance-authority';

export const spinnerStyles = cva('animate-spin text-current', {
  variants: {
    size: {
      sm: 'h-3 w-3',
      md: 'h-4 w-4',
      lg: 'h-6 w-6',
    },
  },
  defaultVariants: {
    size: 'md',
  },
});
