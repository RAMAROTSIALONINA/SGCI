import type * as React from 'react';
import type * as SelectPrimitive from '@radix-ui/react-select';
import type { VariantProps } from 'class-variance-authority';

import type { selectTriggerStyles } from './select.styles';

export type SelectTriggerProps = React.ComponentPropsWithoutRef<
  typeof SelectPrimitive.Trigger
> &
  VariantProps<typeof selectTriggerStyles>;
