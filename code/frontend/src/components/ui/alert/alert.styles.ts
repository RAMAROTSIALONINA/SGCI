import { cva } from 'class-variance-authority';

export const alertVariants = cva(
  'relative w-full rounded-2xl border border-border/70 bg-surface px-4 py-3 text-sm text-foreground shadow-soft [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-foreground [&>svg~*]:pl-8',
  {
    variants: {
      variant: {
        default: 'bg-surface text-foreground',
        destructive:
          'border-destructive/50 bg-destructive/5 text-destructive dark:border-destructive [&>svg]:text-destructive',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
);

export const alertTitleStyles = cva('mb-1 text-sm font-semibold leading-none tracking-tight');

export const alertDescriptionStyles = cva('text-sm text-muted-foreground [&_p]:leading-relaxed');
