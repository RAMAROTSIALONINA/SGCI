'use client';

import { Eye, EyeOff } from 'lucide-react';
import * as React from 'react';

import { cn } from '@/components/utils';

import { inputStyles } from './input.styles';
import type { InputProps } from './input.types';

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, size, tone = 'default', type = 'text', ...props }, ref) => {
    const isPassword = type === 'password';
    const [isVisible, setIsVisible] = React.useState(false);
    const inputType = isPassword ? (isVisible ? 'text' : 'password') : type;

    if (!isPassword) {
      return (
        <input
          ref={ref}
          type={type}
          className={cn(inputStyles({ size, tone }), className)}
          data-invalid={tone === 'error' ? 'true' : undefined}
          {...props}
        />
      );
    }

    return (
      <div className="relative w-full">
        <input
          ref={ref}
          type={inputType}
          className={cn(inputStyles({ size, tone }), 'pr-12', className)}
          data-invalid={tone === 'error' ? 'true' : undefined}
          {...props}
        />
        <button
          type="button"
          onClick={() => setIsVisible((prev) => !prev)}
          className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-1 text-muted-foreground transition hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60"
          aria-label={isVisible ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
          disabled={props.disabled}
        >
          {isVisible ? (
            <EyeOff className="h-4 w-4" aria-hidden="true" />
          ) : (
            <Eye className="h-4 w-4" aria-hidden="true" />
          )}
        </button>
      </div>
    );
  },
);
Input.displayName = 'Input';

export { Input };
