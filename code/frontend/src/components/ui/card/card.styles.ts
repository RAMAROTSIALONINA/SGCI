import { cva } from 'class-variance-authority';

export const cardStyles = cva(
  'rounded-2xl border border-border/70 bg-card text-card-foreground shadow-soft transition-shadow duration-200 ease-[var(--transition-smooth)] backdrop-blur-sm',
  {
    variants: {
      padding: {
        none: 'p-0',
        sm: 'p-4',
        md: 'p-6',
      },
      interactive: {
        true: 'hover:shadow-soft-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
      },
    },
    defaultVariants: {
      padding: 'md',
    },
  },
);

export const cardHeaderStyles = cva('flex flex-col space-y-2');
export const cardTitleStyles = cva('text-xl font-semibold tracking-tight');
export const cardDescriptionStyles = cva('text-sm text-muted-foreground');
export const cardContentStyles = cva('pt-0');
export const cardFooterStyles = cva('flex items-center pt-0');
