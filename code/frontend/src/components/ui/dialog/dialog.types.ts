import type * as DialogPrimitive from '@radix-ui/react-dialog';
import type * as React from 'react';

export type DialogContentProps = React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>;

export type DialogOverlayProps = React.ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay>;

export type DialogTitleProps = React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>;

export type DialogDescriptionProps = React.ComponentPropsWithoutRef<
  typeof DialogPrimitive.Description
>;
