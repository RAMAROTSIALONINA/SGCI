import { Slot as RadixSlot } from '@radix-ui/react-slot';
import * as React from 'react';

type SlotProps = React.HTMLAttributes<HTMLElement> & {
  as?: React.ElementType;
  asChild?: boolean;
};

const Slot = React.forwardRef<HTMLElement, SlotProps>(function SlotInner(
  { as, asChild, ...props },
  ref,
) {
  const Component = asChild ? RadixSlot : (as ?? 'div');
  return <Component ref={ref} {...props} />;
});

Slot.displayName = 'Slot';

export { Slot };
