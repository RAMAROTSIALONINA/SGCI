import { Loader2Icon } from 'lucide-react';

import { cn } from '@/components/utils';

import { spinnerStyles } from './spinner.styles';
import type { SpinnerProps } from './spinner.types';

function Spinner({ className, size, ...props }: SpinnerProps) {
  return (
    <Loader2Icon
      role="status"
      aria-label="Loading"
      className={cn(spinnerStyles({ size }), className)}
      {...props}
    />
  );
}

export { Spinner };
