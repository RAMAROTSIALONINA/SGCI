'use client';

import { LogOut } from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import * as React from 'react';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components';
import { cn } from '@/components/utils';
import { fetchRoles } from '@/features/gestion-des-utilisateurs';
import { fetchCurrentUser, fetchNotifications } from '@/lib/api';
import { clearAuthTokens, getAccessToken } from '@/lib/auth/tokens';
import { formatRoleLabel, normalizeRoleCode, resolveAssistantStatus } from '@/lib/roles';

import { primaryItems, secondaryItems } from './navbar.items';
import { navbarStyles } from './navbar.styles';

type DashboardSidebarProps = {
  className?: string;
};

export function DashboardSidebar({ className }: DashboardSidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [isExpanded, setIsExpanded] = React.useState(false);
  const [logoError, setLogoError] = React.useState(false);
  const [firstName, setFirstName] = React.useState('');
  const [roleLabel, setRoleLabel] = React.useState('');
  const [hideUserManagement, setHideUserManagement] = React.useState(true);
  const [isLogoutDialogOpen, setIsLogoutDialogOpen] = React.useState(false);
  const [unreadNotifications, setUnreadNotifications] = React.useState(0);
  const isHoveringRef = React.useRef(false);

  React.useEffect(() => {
    const controller = new AbortController();
    const pollIntervalMs = 30_000;

    const loadUser = async () => {
      if (typeof window === 'undefined') {
        return;
      }
      const token = getAccessToken();
      if (!token) {
        return;
      }

      try {
        const user = await fetchCurrentUser(token, controller.signal);
        setFirstName(user.first_name);
        setRoleLabel(formatRoleLabel(user.role));

        const roleKey = normalizeRoleCode(user.role);
        if (!roleKey) {
          setHideUserManagement(true);
          return;
        }

        let isAssistant = roleKey.startsWith('assistant');
        try {
          const roles = await fetchRoles(token, controller.signal);
          const roleMatch = resolveAssistantStatus(roleKey, roles);
          if (typeof roleMatch === 'boolean') {
            isAssistant = roleMatch;
          }
        } catch {
          // Keep fallback when roles lookup fails.
        }

        setHideUserManagement(isAssistant);
      } catch {
        // Ignore errors; navbar can render without the name.
        setHideUserManagement(true);
      }
    };

    const loadNotifications = async () => {
      if (typeof window === 'undefined') {
        return;
      }
      const token = getAccessToken();
      if (!token) {
        return;
      }
      try {
        const notifications = await fetchNotifications(token, controller.signal);
        const unreadCount = notifications.filter((item) => !item.is_read).length;
        setUnreadNotifications(unreadCount);
      } catch {
        setUnreadNotifications(0);
      }
    };

    loadUser();
    loadNotifications();

    const handleNotificationsUpdated = () => {
      loadNotifications();
    };

    const pollId = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        loadNotifications();
      }
    }, pollIntervalMs);

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        loadNotifications();
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('sgci-notifications-updated', handleNotificationsUpdated);
      document.addEventListener('visibilitychange', handleVisibilityChange);
      window.addEventListener('focus', handleVisibilityChange);
    }

    return () => {
      controller.abort();
      window.clearInterval(pollId);
      if (typeof window !== 'undefined') {
        window.removeEventListener('sgci-notifications-updated', handleNotificationsUpdated);
        document.removeEventListener('visibilitychange', handleVisibilityChange);
        window.removeEventListener('focus', handleVisibilityChange);
      }
    };
  }, []);

  const visiblePrimaryItems = React.useMemo(() => {
    if (hideUserManagement) {
      return primaryItems.filter((item) => item.href !== '/gestion-des-utilisateurs');
    }
    return primaryItems;
  }, [hideUserManagement]);

  const handleLogout = React.useCallback(() => {
    if (typeof window === 'undefined') {
      return;
    }
    clearAuthTokens();
    setFirstName('');
    setHideUserManagement(true);
    setIsExpanded(false);
    router.push('/');
  }, [router]);

  const handleMouseEnter = React.useCallback(() => {
    isHoveringRef.current = true;
    if (!isLogoutDialogOpen) {
      setIsExpanded(true);
    }
  }, [isLogoutDialogOpen]);

  const handleMouseLeave = React.useCallback(() => {
    isHoveringRef.current = false;
    setIsExpanded(false);
  }, []);

  const handleLogoError = React.useCallback(() => {
    setLogoError(true);
  }, []);

  const handleLogoutDialogChange = React.useCallback((open: boolean) => {
    setIsLogoutDialogOpen(open);
    setIsExpanded(false);
    if (!open) {
      isHoveringRef.current = false;
    }
  }, []);

  return (
    <aside
      className={cn(
        navbarStyles.container,
        isExpanded ? navbarStyles.containerExpanded : navbarStyles.containerCollapsed,
        className,
      )}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <div className={navbarStyles.header}>
        <div className={navbarStyles.brand}>
          <div className={navbarStyles.brandBadge}>
            {!logoError ? (
              <Image
                src="/brand/logo_swis.png"
                alt="SGCI"
                width={40}
                height={40}
                className={navbarStyles.brandLogo}
                onError={handleLogoError}
              />
            ) : (
              <span className={navbarStyles.brandFallback}>SG</span>
            )}
          </div>
          <div
            className={cn(
              navbarStyles.brandText,
              isExpanded ? navbarStyles.brandTextExpanded : navbarStyles.brandTextCollapsed,
            )}
          >
            <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">SGCI</p>
            <p className="text-base font-semibold text-foreground">
              {roleLabel || 'Operations Hub'}
            </p>
          </div>
        </div>
        <span className={navbarStyles.statusDot} aria-hidden="true" />
      </div>

      {firstName ? (
        <div className={navbarStyles.user}>
          <span
            className={cn(
              navbarStyles.userLabel,
              isExpanded ? navbarStyles.userLabelExpanded : navbarStyles.userLabelCollapsed,
            )}
          >
            Bonjour
          </span>
          <span
            className={cn(
              navbarStyles.userName,
              isExpanded ? navbarStyles.userNameExpanded : navbarStyles.userNameCollapsed,
            )}
          >
            {firstName}
          </span>
        </div>
      ) : null}

      <nav className={navbarStyles.nav}>
        {visiblePrimaryItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            typeof pathname === 'string' &&
            (item.href === '/dashboard'
              ? pathname === item.href
              : pathname === item.href ||
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
                  isExpanded ? navbarStyles.labelExpanded : navbarStyles.labelCollapsed,
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
          const isNotifications = item.href === '/notifications';
          const unreadLabel = unreadNotifications > 99 ? '99+' : String(unreadNotifications);
          const showUnread = isNotifications && unreadNotifications > 0;
          const isActive =
            typeof pathname === 'string' &&
            (pathname === item.href || (item.href !== '/' && pathname.startsWith(`${item.href}/`)));
          return (
            <Link
              key={item.label}
              href={item.href}
              className={cn(navbarStyles.secondaryLink, isActive && navbarStyles.linkActive)}
            >
              <span className={cn(navbarStyles.secondaryIcon, isActive && navbarStyles.iconActive)}>
                <Icon className="h-4 w-4" aria-hidden="true" />
                {showUnread ? (
                  <span className={navbarStyles.notificationCount}>{unreadLabel}</span>
                ) : null}
              </span>
              <span
                className={cn(
                  navbarStyles.label,
                  isExpanded ? navbarStyles.labelExpanded : navbarStyles.labelCollapsed,
                )}
              >
                {item.label}
              </span>
            </Link>
          );
        })}
        <AlertDialog onOpenChange={handleLogoutDialogChange}>
          <AlertDialogTrigger asChild>
            <button type="button" className={navbarStyles.secondaryLink}>
              <span className={navbarStyles.secondaryIcon}>
                <LogOut className="h-4 w-4" aria-hidden="true" />
              </span>
              <span
                className={cn(
                  navbarStyles.label,
                  isExpanded ? navbarStyles.labelExpanded : navbarStyles.labelCollapsed,
                )}
              >
                Deconnexion
              </span>
            </button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Se deconnecter ?</AlertDialogTitle>
              <AlertDialogDescription>
                Etes-vous sur de vouloir vous deconnecter ? Vous devrez vous reconnecter pour
                acceder a vos espaces.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Annuler</AlertDialogCancel>
              <AlertDialogAction onClick={handleLogout}>Confirmer</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </aside>
  );
}
