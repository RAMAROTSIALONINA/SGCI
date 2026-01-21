'use client';

import * as React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

import { cn } from '@/components/utils';

import { primaryItems, secondaryItems } from './navbar.items';
import { navbarStyles } from './navbar.styles';

type DashboardSidebarProps = {
  className?: string;
};

export function DashboardSidebar({ className }: DashboardSidebarProps) {
  const pathname = usePathname();
  const [isExpanded, setIsExpanded] = React.useState(false);

  return (
    <aside
      className={cn(
        navbarStyles.container,
        isExpanded ? navbarStyles.containerExpanded : navbarStyles.containerCollapsed,
        className,
      )}
      onMouseEnter={() => setIsExpanded(true)}
      onMouseLeave={() => setIsExpanded(false)}
    >
      <div className={navbarStyles.header}>
        <div className={navbarStyles.brand}>
          <div className={navbarStyles.brandBadge}>
            SG
          </div>
          <div
            className={cn(
              navbarStyles.brandText,
              isExpanded
                ? navbarStyles.brandTextExpanded
                : navbarStyles.brandTextCollapsed,
            )}
          >
            <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
              SGCI
            </p>
            <p className="text-base font-semibold text-foreground">
              Operations Hub
            </p>
          </div>
        </div>
        <span className={navbarStyles.statusDot} aria-hidden="true" />
      </div>

      <nav className={navbarStyles.nav}>
        {primaryItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            typeof pathname === 'string' &&
            (pathname === item.href ||
              (item.href !== '/' && pathname.startsWith(`${item.href}/`)));

          return (
            <Link
              key={item.label}
              href={item.href}
              className={cn(
                navbarStyles.linkBase,
                isActive ? navbarStyles.linkActive : navbarStyles.linkInactive,
              )}
            >
              <span
                className={cn(
                  navbarStyles.iconBase,
                  isActive ? navbarStyles.iconActive : navbarStyles.iconInactive,
                )}
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
              </span>
              <span
                className={cn(
                  navbarStyles.label,
                  isExpanded
                    ? navbarStyles.labelExpanded
                    : navbarStyles.labelCollapsed,
                )}
              >
                {item.label}
              </span>
            </Link>
          );
        })}
      </nav>

      <div className={navbarStyles.secondaryWrapper}>
        {secondaryItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            typeof pathname === 'string' &&
            (pathname === item.href ||
              (item.href !== '/' && pathname.startsWith(`${item.href}/`)));
          return (
            <Link
              key={item.label}
              href={item.href}
              className={cn(
                navbarStyles.secondaryLink,
                isActive && navbarStyles.linkActive,
              )}
            >
              <span
                className={cn(
                  navbarStyles.secondaryIcon,
                  isActive && navbarStyles.iconActive,
                )}
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
              </span>
              <span
                className={cn(
                  navbarStyles.label,
                  isExpanded
                    ? navbarStyles.labelExpanded
                    : navbarStyles.labelCollapsed,
                )}
              >
                {item.label}
              </span>
            </Link>
          );
        })}
      </div>
    </aside>
  );
}
