'use client';

import { usePathname, useRouter } from 'next/navigation';

import { cn } from '@/components/utils';

import { Button } from '../button';
import { miniMenuStyles } from './mini-menu.styles';
import type { MiniMenuProps } from './mini-menu.types';

export function MiniMenu({
  items,
  activeItem,
  className,
  ariaLabel = 'Menu',
  onItemClick,
}: MiniMenuProps) {
  const pathname = usePathname();
  const router = useRouter();
  const matchedItem = items.find((item) => item.href && pathname === item.href);
  const defaultActive = activeItem ?? matchedItem?.id ?? items[0]?.id;

  return (
    <div className={cn(miniMenuStyles.container, className)} role="group" aria-label={ariaLabel}>
      {items.map((item) => {
        const isActive = item.id === defaultActive;
        const href = item.href;
        const handleClick = onItemClick
          ? () => onItemClick(item)
          : href && !item.disabled
            ? () => router.push(href)
            : undefined;

        return (
          <Button
            key={item.id}
            type="button"
            size="sm"
            variant={isActive ? 'default' : 'ghost'}
            className={cn(
              miniMenuStyles.buttonBase,
              isActive ? miniMenuStyles.buttonActive : miniMenuStyles.buttonInactive,
            )}
            onClick={handleClick}
            disabled={item.disabled}
            aria-pressed={isActive}
          >
            {item.label}
          </Button>
        );
      })}
    </div>
  );
}
