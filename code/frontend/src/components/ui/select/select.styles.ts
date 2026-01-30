import { cva } from 'class-variance-authority';

export const selectTriggerStyles = cva(
  'flex w-full items-center justify-between gap-3 rounded-xl border border-border/80 bg-surface px-3 text-sm font-medium text-foreground shadow-soft transition-all duration-200 ease-[var(--transition-smooth)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60 [&>span]:line-clamp-1',
  {
    variants: {
      size: {
        sm: 'h-9',
        md: 'h-11',
        lg: 'h-12 px-4 text-base',
      },
      tone: {
        default: '',
        error: 'border-destructive/70 focus-visible:ring-destructive/60',
      },
    },
    defaultVariants: {
      size: 'md',
      tone: 'default',
    },
  },
);

export const selectContentStyles = cva(
  'relative z-50 max-h-[--radix-select-content-available-height] min-w-[10rem] overflow-hidden rounded-2xl border border-border/80 bg-popover text-popover-foreground shadow-soft-lg backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 origin-[--radix-select-content-transform-origin]',
);

export const selectViewportStyles = cva('p-1');
export const selectScrollButtonStyles = cva(
  'flex cursor-default items-center justify-center py-1 text-muted-foreground',
);
export const selectLabelStyles = cva(
  'px-3 py-2 text-xs font-semibold uppercase tracking-widest text-muted-foreground',
);
export const selectItemStyles = cva(
  'relative flex w-full cursor-default select-none items-center gap-2 rounded-xl py-2 pl-3 pr-8 text-sm font-medium outline-none transition-colors focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
);
export const selectSeparatorStyles = cva('my-1 h-px bg-border/70');
