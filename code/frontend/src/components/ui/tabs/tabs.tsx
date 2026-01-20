'use client';

import * as React from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';

import { cn } from '@/components/utils';

import { tabsContentStyles, tabsListStyles, tabsTriggerStyles } from './tabs.styles';
import type { TabsListProps, TabsTriggerProps } from './tabs.types';

const Tabs = TabsPrimitive.Root;

const TabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  TabsListProps
>(({ className, size, style, ...props }, ref) => {
  const listRef = React.useRef<React.ElementRef<typeof TabsPrimitive.List>>(null);

  const setRefs = React.useCallback(
    (node: React.ElementRef<typeof TabsPrimitive.List> | null) => {
      listRef.current = node;
      if (typeof ref === 'function') {
        ref(node);
      } else if (ref) {
        ref.current = node;
      }
    },
    [ref],
  );

  const updateIndicator = React.useCallback(() => {
    const list = listRef.current;
    if (!list) return;

    const activeTrigger = list.querySelector<HTMLElement>('[data-state="active"]');
    if (!activeTrigger) {
      list.style.setProperty('--tabs-indicator-x', '0px');
      list.style.setProperty('--tabs-indicator-w', '0px');
      list.style.setProperty('--tabs-indicator-opacity', '0');
      return;
    }

    const listRect = list.getBoundingClientRect();
    const activeRect = activeTrigger.getBoundingClientRect();
    const x = activeRect.left - listRect.left;
    const width = activeRect.width;

    list.style.setProperty('--tabs-indicator-x', `${x}px`);
    list.style.setProperty('--tabs-indicator-w', `${width}px`);
    list.style.setProperty('--tabs-indicator-opacity', '1');
  }, []);

  React.useLayoutEffect(() => {
    const list = listRef.current;
    if (!list) return;

    updateIndicator();

    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(updateIndicator);
      resizeObserver.observe(list);
    }

    let mutationObserver: MutationObserver | null = null;
    if (typeof MutationObserver !== 'undefined') {
      mutationObserver = new MutationObserver(updateIndicator);
      mutationObserver.observe(list, {
        attributes: true,
        subtree: true,
        attributeFilter: ['data-state'],
      });
    }

    const handleResize = () => updateIndicator();
    window.addEventListener('resize', handleResize);

    return () => {
      resizeObserver?.disconnect();
      mutationObserver?.disconnect();
      window.removeEventListener('resize', handleResize);
    };
  }, [updateIndicator]);

  const listStyle = {
    '--tabs-indicator-x': '0px',
    '--tabs-indicator-w': '0px',
    '--tabs-indicator-opacity': 0,
    ...style,
  } as React.CSSProperties;

  return (
    <TabsPrimitive.List
      ref={setRefs}
      className={cn(tabsListStyles({ size }), className)}
      style={listStyle}
      {...props}
    />
  );
});
TabsList.displayName = TabsPrimitive.List.displayName;

const TabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  TabsTriggerProps
>(({ className, size, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(tabsTriggerStyles({ size }), className)}
    {...props}
  />
));
TabsTrigger.displayName = TabsPrimitive.Trigger.displayName;

const TabsContent = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Content
    ref={ref}
    className={cn(tabsContentStyles(), className)}
    {...props}
  />
));
TabsContent.displayName = TabsPrimitive.Content.displayName;

export { Tabs, TabsList, TabsTrigger, TabsContent };
