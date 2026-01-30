import { cva } from 'class-variance-authority';

export const tooltipContentStyles = cva(
  'z-50 overflow-hidden rounded-xl border border-border/70 bg-popover px-3 py-1.5 text-xs font-medium text-popover-foreground shadow-soft backdrop-blur-sm transition-all duration-150 ease-[var(--transition-smooth)] data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 origin-[--radix-tooltip-content-transform-origin]',
  {
    variants: {
      tone: {
        default: '',
        inverted: 'bg-foreground text-background border-transparent',
      },
    },
    defaultVariants: {
      tone: 'default',
    },
  },
);
