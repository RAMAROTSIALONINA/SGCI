import { cva } from 'class-variance-authority';

export const avatarRootStyles = cva(
  'relative flex shrink-0 overflow-hidden rounded-full border border-border/70 bg-surface shadow-soft',
  {
    variants: {
      size: {
        sm: 'h-8 w-8',
        md: 'h-10 w-10',
        lg: 'h-12 w-12',
      },
    },
    defaultVariants: {
      size: 'md',
    },
  },
);

export const avatarImageStyles = cva('aspect-square h-full w-full');
export const avatarFallbackStyles = cva(
  'flex h-full w-full items-center justify-center rounded-full bg-surface-muted text-xs font-semibold text-muted-foreground',
);
