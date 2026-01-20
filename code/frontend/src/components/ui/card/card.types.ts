import type * as React from 'react';
import type { VariantProps } from 'class-variance-authority';

import type { cardStyles } from './card.styles';

export type CardProps = React.HTMLAttributes<HTMLDivElement> &
  VariantProps<typeof cardStyles>;

export type CardSectionProps = React.HTMLAttributes<HTMLDivElement>;
