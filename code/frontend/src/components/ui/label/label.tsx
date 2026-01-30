'use client';

import * as LabelPrimitive from '@radix-ui/react-label';
import * as React from 'react';

import { cn } from '@/components/utils';

import { labelStyles } from './label.styles';
import type { LabelProps } from './label.types';

const Label = React.forwardRef<React.ElementRef<typeof LabelPrimitive.Root>, LabelProps>(
  ({ className, size, tone, ...props }, ref) => (
    <LabelPrimitive.Root
      ref={ref}
      className={cn(labelStyles({ size, tone }), className)}
      {...props}
    />
  ),
);
Label.displayName = LabelPrimitive.Root.displayName;

export { Label };
