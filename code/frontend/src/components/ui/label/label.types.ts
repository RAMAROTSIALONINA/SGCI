import type * as React from 'react';
import type * as LabelPrimitive from '@radix-ui/react-label';
import type { VariantProps } from 'class-variance-authority';

import type { labelStyles } from './label.styles';

export type LabelProps = React.ComponentPropsWithoutRef<
  typeof LabelPrimitive.Root
> &
  VariantProps<typeof labelStyles>;
