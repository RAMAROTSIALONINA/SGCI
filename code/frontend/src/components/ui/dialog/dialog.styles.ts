import { cva } from 'class-variance-authority';

export const dialogOverlayStyles = cva(
  'fixed inset-0 z-50 bg-black/65 backdrop-blur-sm transition-opacity data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=open]:fade-in-0 data-[state=closed]:fade-out-0',
);

export const dialogContentStyles = cva(
  'fixed left-1/2 top-1/2 z-50 grid w-full max-w-xl -translate-x-1/2 -translate-y-1/2 gap-5 rounded-3xl border border-border/70 bg-surface text-foreground shadow-soft-lg duration-200 ease-[var(--transition-smooth)] data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
);

export const dialogHeaderStyles = cva('flex flex-col gap-1.5 text-left sm:text-left');

export const dialogFooterStyles = cva('flex flex-col-reverse gap-2 sm:flex-row sm:justify-end');

export const dialogTitleStyles = cva('text-xl font-semibold tracking-tight');

export const dialogDescriptionStyles = cva('text-sm text-muted-foreground');

export const dialogCloseButtonStyles = cva(
  'absolute right-4 top-4 inline-flex items-center justify-center rounded-full p-2 text-muted-foreground transition-colors duration-150 hover:bg-accent/70 hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
);
