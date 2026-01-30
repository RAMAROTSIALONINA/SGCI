import { cn } from '@/components/utils';

import { skeletonStyles } from './skeleton.styles';
import type { SkeletonProps } from './skeleton.types';

function Skeleton({ className, size, ...props }: SkeletonProps) {
  return <div className={cn(skeletonStyles({ size }), className)} {...props} />;
}

export { Skeleton };
