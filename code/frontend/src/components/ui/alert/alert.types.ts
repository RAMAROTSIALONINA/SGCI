import type { VariantProps } from 'class-variance-authority';
import type * as React from 'react';

import type { alertVariants } from './alert.styles';

export type AlertProps = React.HTMLAttributes<HTMLDivElement> & VariantProps<typeof alertVariants>;
export type AlertTitleProps = React.HTMLAttributes<HTMLHeadingElement>;
export type AlertDescriptionProps = React.HTMLAttributes<HTMLParagraphElement>;
