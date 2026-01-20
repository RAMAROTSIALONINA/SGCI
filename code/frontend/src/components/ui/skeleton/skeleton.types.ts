import type * as React from 'react';
import type { VariantProps } from 'class-variance-authority';

import type { skeletonStyles } from './skeleton.styles';

export interface SkeletonProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof skeletonStyles> {}
