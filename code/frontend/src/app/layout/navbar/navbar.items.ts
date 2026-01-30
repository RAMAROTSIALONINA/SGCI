import type { LucideIcon } from 'lucide-react';
import { Bell, History, LayoutDashboard, Settings, UsersRound } from 'lucide-react';

type NavItem = {
  label: string;
  href: string;
  icon: LucideIcon;
};

export const primaryItems: NavItem[] = [
  {
    label: 'Overview',
    href: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    label: 'Gestion des utilisateurs',
    href: '/gestion-des-utilisateurs',
    icon: UsersRound,
  },
];

export const secondaryItems: NavItem[] = [
  {
    label: 'Parametre',
    href: '/dashboard/settings',
    icon: Settings,
  },
  {
    label: 'Notifications',
    href: '/notifications',
    icon: Bell,
  },
  {
    label: 'Historique',
    href: '/historique',
    icon: History,
  },
];
