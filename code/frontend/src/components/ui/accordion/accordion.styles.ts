import { cva } from 'class-variance-authority';

export const accordionItemStyles = cva('border-b border-border/70 bg-surface transition-colors');

export const accordionTriggerStyles = cva(
  'flex w-full items-center justify-between gap-4 py-4 text-left text-sm font-semibold text-foreground transition-all duration-200 ease-[var(--transition-smooth)] hover:text-foreground/80 [&[data-state=open]>svg]:rotate-180',
);

export const accordionContentStyles = cva(
  'overflow-hidden text-sm text-muted-foreground data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down',
);

export const accordionContentInnerStyles = cva('pb-4 pt-0');
