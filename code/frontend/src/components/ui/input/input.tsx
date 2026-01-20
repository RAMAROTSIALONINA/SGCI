import * as React from 'react';

import { cn } from '@/components/utils';

import { inputStyles } from './input.styles';
import type { InputProps } from './input.types';

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, size, tone = 'default', type = 'text', ...props }, ref) => {
    return (
      <input
        ref={ref}
        type={type}
        className={cn(inputStyles({ size, tone }), className)}
        data-invalid={tone === 'error' ? 'true' : undefined}
        {...props}
      />
    );
  },
);
Input.displayName = 'Input';

export { Input };
