import { cva } from 'class-variance-authority';

export const sheetOverlayStyles = cva(
  'fixed inset-0 z-50 bg-black/60 backdrop-blur-sm transition-opacity data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0',
);

export const sheetContentStyles = cva(
  'fixed z-50 flex flex-col gap-4 bg-surface p-6 text-foreground shadow-soft-lg transition duration-200 ease-[var(--transition-smooth)] data-[state=open]:animate-in data-[state=closed]:animate-out',
  {
    variants: {
      side: {
        top: 'inset-x-0 top-0 border-b border-border/70 data-[state=closed]:slide-out-to-top data-[state=open]:slide-in-from-top',
        bottom:
          'inset-x-0 bottom-0 border-t border-border/70 data-[state=closed]:slide-out-to-bottom data-[state=open]:slide-in-from-bottom',
        left: 'inset-y-0 left-0 h-full w-3/4 border-r border-border/70 data-[state=closed]:slide-out-to-left data-[state=open]:slide-in-from-left sm:max-w-sm',
        right:
          'inset-y-0 right-0 h-full w-3/4 border-l border-border/70 data-[state=closed]:slide-out-to-right data-[state=open]:slide-in-from-right sm:max-w-sm',
      },
    },
    defaultVariants: {
      side: 'right',
    },
  },
);

export const sheetHeaderStyles = cva('flex flex-col gap-2 text-left');
export const sheetFooterStyles = cva('flex flex-col-reverse gap-2 sm:flex-row sm:justify-end');
export const sheetTitleStyles = cva('text-lg font-semibold tracking-tight');
export const sheetDescriptionStyles = cva('text-sm text-muted-foreground');
export const sheetCloseStyles = cva(
  'absolute right-4 top-4 inline-flex items-center justify-center rounded-full p-2 text-muted-foreground transition-colors hover:bg-accent/70 hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
);
