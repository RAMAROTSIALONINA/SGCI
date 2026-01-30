import { cva } from 'class-variance-authority';

export const tableWrapperStyles = cva(
  'relative w-full overflow-auto rounded-2xl border border-border/70 bg-[linear-gradient(180deg,_rgba(var(--palette-primary-rgb)_/_0.04),_rgba(var(--palette-accent-rgb)_/_0.08))] shadow-soft',
);

export const tableStyles = cva('w-full caption-bottom text-sm');
export const tableHeaderStyles = cva(
  'sticky top-0 z-10 border-b border-border/80 bg-[rgba(var(--palette-primary-rgb)_/_0.18)] backdrop-blur [&_tr]:border-b-0',
);
export const tableBodyStyles = cva('[&_tr:last-child]:border-0');
export const tableFooterStyles = cva(
  'border-t border-border/70 bg-[rgba(var(--palette-primary-rgb)_/_0.06)] font-medium [&>tr]:last:border-b-0',
);
export const tableRowStyles = cva(
  'border-b border-border/70 transition-colors even:bg-[rgba(var(--palette-primary-rgb)_/_0.03)] hover:bg-[rgba(var(--palette-accent-rgb)_/_0.12)] data-[state=selected]:bg-[rgba(var(--palette-primary-rgb)_/_0.12)]',
);
export const tableHeadStyles = cva(
  'h-12 px-4 text-left align-middle text-[0.72rem] font-bold uppercase tracking-[0.18em] text-foreground/90 [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]',
);
export const tableCellStyles = cva(
  'p-4 align-middle text-sm [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]',
);
export const tableCaptionStyles = cva('px-4 pb-4 text-sm text-muted-foreground');
