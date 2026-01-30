import * as React from 'react';

import { cn } from '@/components/utils';

import { textareaStyles } from './textarea.styles';
import type { TextareaProps } from './textarea.types';

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, tone = 'default', ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(textareaStyles({ tone }), className)}
      data-invalid={tone === 'error' ? 'true' : undefined}
      {...props}
    />
  ),
);
Textarea.displayName = 'Textarea';

export { Textarea };
