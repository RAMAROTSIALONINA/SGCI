import { cva } from 'class-variance-authority';

export const paginationRootStyles = cva('mx-auto flex w-full justify-center');
export const paginationListStyles = cva('flex items-center gap-1');
export const paginationItemStyles = cva('');
export const paginationEllipsisStyles = cva(
  'flex h-9 w-9 items-center justify-center rounded-full border border-border/70 bg-surface-muted text-muted-foreground',
);
