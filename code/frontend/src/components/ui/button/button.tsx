import { Slot } from '@radix-ui/react-slot';
import * as React from 'react';

import { cn } from '@/components/utils';

import { buttonVariants } from './button.styles';
import type { ButtonProps } from './button.types';

const SpinnerIcon = ({ className }: { className?: string }) => (
  <svg
    aria-hidden="true"
    viewBox="0 0 24 24"
    className={cn('animate-spin text-current', className)}
  >
    <circle
      className="opacity-20"
      cx="12"
      cy="12"
      r="10"
      stroke="currentColor"
      strokeWidth="4"
      fill="none"
    />
    <path
      className="opacity-70"
      fill="currentColor"
      d="M22 12c0-5.523-4.477-10-10-10a1 1 0 0 0 0 2c4.418 0 8 3.582 8 8a1 1 0 1 0 2 0Z"
    />
  </svg>
);

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, isLoading = false, children, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    const disabled = props.disabled || isLoading;

    return (
      <Comp
        ref={ref}
        className={cn(
          buttonVariants({ variant, size, loading: isLoading, className }),
          'focus-visible:ring-offset-2',
        )}
        data-loading={isLoading ? 'true' : undefined}
        aria-busy={isLoading ? true : undefined}
        disabled={disabled}
        {...props}
      >
        {isLoading && (
          <>
            <SpinnerIcon className="size-4" />
            <span className="sr-only">Chargement</span>
          </>
        )}
        <span className={cn(isLoading && 'opacity-80')}>{children}</span>
      </Comp>
    );
  },
);
Button.displayName = 'Button';

export { Button, buttonVariants };
