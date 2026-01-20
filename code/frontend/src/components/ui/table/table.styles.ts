import { cva } from 'class-variance-authority';

export const tableWrapperStyles = cva(
  'relative w-full overflow-auto rounded-2xl border border-border/70 bg-surface shadow-soft',
);

export const tableStyles = cva('w-full caption-bottom text-sm');
export const tableHeaderStyles = cva('[&_tr]:border-b');
export const tableBodyStyles = cva('[&_tr:last-child]:border-0');
export const tableFooterStyles = cva(
  'border-t border-border/70 bg-surface-muted font-medium [&>tr]:last:border-b-0',
);
export const tableRowStyles = cva(
  'border-b border-border/70 transition-colors hover:bg-accent/60 data-[state=selected]:bg-accent/80',
);
export const tableHeadStyles = cva(
  'h-11 px-4 text-left align-middle text-xs font-semibold uppercase tracking-wide text-muted-foreground [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]',
);
export const tableCellStyles = cva(
  'p-4 align-middle text-sm [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]',
);
export const tableCaptionStyles = cva('px-4 pb-4 text-sm text-muted-foreground');
