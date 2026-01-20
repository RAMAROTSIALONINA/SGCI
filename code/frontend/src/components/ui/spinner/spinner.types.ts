import type * as React from 'react';
import type { VariantProps } from 'class-variance-authority';

import type { spinnerStyles } from './spinner.styles';

export interface SpinnerProps
  extends React.ComponentProps<'svg'>,
    VariantProps<typeof spinnerStyles> {}
