'use client';

import * as React from 'react';
import * as SwitchPrimitives from '@radix-ui/react-switch';

import { cn } from '@/components/utils';

import { switchRootStyles, switchThumbStyles } from './switch.styles';
import type { SwitchProps } from './switch.types';

const Switch = React.forwardRef<
  React.ElementRef<typeof SwitchPrimitives.Root>,
  SwitchProps
>(({ className, size, ...props }, ref) => (
  <SwitchPrimitives.Root
    ref={ref}
    className={cn(switchRootStyles({ size }), className)}
    {...props}
  >
    <SwitchPrimitives.Thumb className={switchThumbStyles({ size })} />
  </SwitchPrimitives.Root>
));
Switch.displayName = SwitchPrimitives.Root.displayName;

export { Switch };
