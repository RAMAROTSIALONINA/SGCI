import * as React from 'react';

import { cn } from '@/components/utils';

import { badgeVariants } from './badge.styles';
import type { BadgeProps } from './badge.types';

const Badge = React.forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant, tone, ...props }, ref) => (
    <div ref={ref} className={cn(badgeVariants({ variant, tone }), className)} {...props} />
  ),
);
Badge.displayName = 'Badge';

export { Badge, badgeVariants };
