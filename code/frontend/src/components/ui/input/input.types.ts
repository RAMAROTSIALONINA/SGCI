import type { VariantProps } from 'class-variance-authority';
import type * as React from 'react';

import type { inputStyles } from './input.styles';

export interface InputProps
  extends
    Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'>,
    VariantProps<typeof inputStyles> {}
