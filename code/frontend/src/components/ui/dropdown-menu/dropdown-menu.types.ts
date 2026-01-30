import type * as DropdownMenuPrimitive from '@radix-ui/react-dropdown-menu';
import type { VariantProps } from 'class-variance-authority';
import type * as React from 'react';

import type {
  dropdownContentStyles,
  dropdownItemStyles,
  dropdownSubTriggerStyles,
} from './dropdown-menu.styles';

export type DropdownMenuContentProps = React.ComponentPropsWithoutRef<
  typeof DropdownMenuPrimitive.Content
> &
  VariantProps<typeof dropdownContentStyles>;

export type DropdownMenuItemProps = React.ComponentPropsWithoutRef<
  typeof DropdownMenuPrimitive.Item
> &
  VariantProps<typeof dropdownItemStyles>;

export type DropdownMenuSubTriggerProps = React.ComponentPropsWithoutRef<
  typeof DropdownMenuPrimitive.SubTrigger
> &
  VariantProps<typeof dropdownSubTriggerStyles>;
