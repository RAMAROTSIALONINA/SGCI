import { cva } from 'class-variance-authority';

export const dropdownContentStyles = cva(
  'z-50 min-w-[10rem] overflow-hidden rounded-2xl border border-border/80 bg-popover text-popover-foreground shadow-soft-lg backdrop-blur-sm outline-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 origin-[--radix-dropdown-menu-content-transform-origin]',
  {
    variants: {
      density: {
        comfy: 'p-2',
        compact: 'p-1',
      },
    },
    defaultVariants: {
      density: 'compact',
    },
  },
);

export const dropdownItemStyles = cva(
  'relative flex cursor-default select-none items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium outline-none transition-colors focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&>svg]:size-4 [&>svg]:shrink-0',
  {
    variants: {
      inset: {
        true: 'pl-9',
      },
    },
  },
);

export const dropdownSubTriggerStyles = cva(
  'flex cursor-default select-none items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium outline-none focus:bg-accent data-[state=open]:bg-accent [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      inset: {
        true: 'pl-9',
      },
    },
  },
);

export const dropdownLabelStyles = cva(
  'px-3 py-2 text-xs font-semibold uppercase tracking-widest text-muted-foreground',
);

export const dropdownSeparatorStyles = cva('my-1 h-px bg-border/70');

export const dropdownShortcutStyles = cva(
  'ml-auto text-xs uppercase tracking-[0.2em] text-muted-foreground/70',
);

export const dropdownCheckboxItemStyles = cva(
  'relative flex cursor-default select-none items-center rounded-xl py-2 pl-9 pr-3 text-sm font-medium outline-none transition-colors focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
);

export const dropdownRadioItemStyles = cva(
  'relative flex cursor-default select-none items-center rounded-xl py-2 pl-9 pr-3 text-sm font-medium outline-none transition-colors focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
);
