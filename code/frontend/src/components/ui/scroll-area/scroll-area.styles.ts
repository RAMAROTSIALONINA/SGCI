import { cva } from 'class-variance-authority';

export const scrollAreaRootStyles = cva('relative overflow-hidden rounded-2xl');
export const scrollAreaViewportStyles = cva('h-full w-full rounded-[inherit]');
export const scrollAreaScrollbarStyles = cva(
  'flex touch-none select-none transition-colors duration-150 ease-[var(--transition-smooth)]',
  {
    variants: {
      orientation: {
        vertical: 'h-full w-2.5 border-l border-l-transparent p-[1px]',
        horizontal: 'h-2.5 flex-col border-t border-t-transparent p-[1px]',
      },
    },
  },
);
export const scrollAreaThumbStyles = cva(
  'relative flex-1 rounded-full bg-border/80 hover:bg-border',
);
