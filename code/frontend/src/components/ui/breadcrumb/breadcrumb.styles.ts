import { cva } from 'class-variance-authority';

export const breadcrumbListStyles = cva(
  'flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground sm:gap-2.5',
);
export const breadcrumbItemStyles = cva('inline-flex items-center gap-1.5');
export const breadcrumbLinkStyles = cva(
  'text-muted-foreground transition-colors hover:text-foreground',
);
export const breadcrumbPageStyles = cva('font-semibold text-foreground');
export const breadcrumbSeparatorStyles = cva('[&>svg]:h-3.5 [&>svg]:w-3.5');
export const breadcrumbEllipsisStyles = cva(
  'flex h-8 w-8 items-center justify-center rounded-full border border-border/70 bg-surface-muted text-muted-foreground',
);
