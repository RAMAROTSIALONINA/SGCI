import type * as React from 'react';
import type { VariantProps } from 'class-variance-authority';

import type { textareaStyles } from './textarea.styles';

export interface TextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement>,
    VariantProps<typeof textareaStyles> {}
