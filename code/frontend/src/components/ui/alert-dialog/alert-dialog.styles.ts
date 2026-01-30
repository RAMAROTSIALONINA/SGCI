import { cva } from 'class-variance-authority';

export const alertDialogOverlayStyles = cva(
  'fixed inset-0 z-50 bg-black/65 backdrop-blur-sm transition-opacity data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0',
);

export const alertDialogContentStyles = cva(
  'fixed left-1/2 top-1/2 z-50 grid w-full max-w-lg -translate-x-1/2 -translate-y-1/2 gap-4 rounded-3xl border border-border/70 bg-surface p-6 text-foreground shadow-soft-lg duration-200 ease-[var(--transition-smooth)] data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:slide-out-to-top-[48%] data-[state=open]:slide-in-from-top-[48%]',
);

export const alertDialogHeaderStyles = cva('flex flex-col gap-2 text-center sm:text-left');

export const alertDialogFooterStyles = cva(
  'flex flex-col-reverse gap-2 sm:flex-row sm:justify-end',
);

export const alertDialogTitleStyles = cva('text-lg font-semibold tracking-tight');
export const alertDialogDescriptionStyles = cva('text-sm text-muted-foreground');
