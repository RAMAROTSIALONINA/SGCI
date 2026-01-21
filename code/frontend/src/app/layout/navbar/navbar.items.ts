import type { LucideIcon } from 'lucide-react';
import {
  LayoutDashboard,
  Settings,
  UsersRound,
} from 'lucide-react';

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
    label: 'Settings',
    href: '/dashboard/settings',
    icon: Settings,
  },
];
