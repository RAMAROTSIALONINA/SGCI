'use client';

import { useTheme } from 'next-themes';
import { Toaster as Sonner } from 'sonner';

import { toasterClassNames } from './sonner.styles';
import type { ToasterProps } from './sonner.types';

const Toaster = ({ ...props }: ToasterProps) => {
  const { theme = 'system' } = useTheme();

  return (
    <Sonner
      theme={theme as ToasterProps['theme']}
      className="toaster group"
      toastOptions={{
        classNames: toasterClassNames,
      }}
      {...props}
    />
  );
};

export { Toaster };
