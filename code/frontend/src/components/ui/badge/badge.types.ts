import type * as React from 'react';
import type { VariantProps } from 'class-variance-authority';

import type { badgeVariants } from './badge.styles';

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}
