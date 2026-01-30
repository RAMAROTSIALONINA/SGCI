'use client';

import * as React from 'react';

import { Card, CardDescription, CardHeader, CardTitle, MiniMenu, PageHeader } from '@/components';
import {
  buildRoleLookup,
  countUsersByRole,
  fetchRoles,
  fetchUsers,
  type RoleApi,
  type UserApi,
} from '@/features/gestion-des-utilisateurs';
import { fetchCurrentUser } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';
import { normalizeRoleCode, resolveAssistantStatus } from '@/lib/roles';

const baseUserMenuItems = [
  { id: 'liste', label: 'Utilisateurs', href: '/gestion-des-utilisateurs/liste' },
  { id: 'role', label: 'Role', href: '/gestion-des-utilisateurs/role' },
];

export default function UsersManagementLayout({ children }: { children: React.ReactNode }) {
  const [hideRoleSection, setHideRoleSection] = React.useState(true);
  const [stats, setStats] = React.useState<{
    admins: number | null;
    roles: number | null;
    assistants: number | null;
  }>({
    admins: null,
    roles: null,
    assistants: null,
  });

  const formatStat = React.useCallback(
    (value: number | null) => (typeof value === 'number' ? value : '--'),
    [],
  );

  React.useEffect(() => {
    const controller = new AbortController();

    const loadUserRole = async () => {
      if (typeof window === 'undefined') {
        return;
      }
      const token = getAccessToken();
      if (!token) {
        return;
      }
      let roleKey = '';
      let rolesResponse: RoleApi[] | null = null;
      try {
        const user = await fetchCurrentUser(token, controller.signal);
        roleKey = normalizeRoleCode(user.role);
      } catch {
        setHideRoleSection(true);
        setStats({ admins: null, roles: null, assistants: null });
        return;
      }

      if (!roleKey) {
        setHideRoleSection(true);
      } else {
        let isAssistant = roleKey.startsWith('assistant');
        try {
          rolesResponse = await fetchRoles(token, controller.signal);
          const roleMatch = resolveAssistantStatus(roleKey, rolesResponse);
          if (typeof roleMatch === 'boolean') {
            isAssistant = roleMatch;
          }
        } catch {
          // Ignore role lookup errors and keep the fallback.
          rolesResponse = null;
        }

        setHideRoleSection(isAssistant);
      }

      let usersResponse: UserApi[] | null = null;
      try {
        usersResponse = await fetchUsers(token, controller.signal);
      } catch {
        usersResponse = null;
      }

      if (!rolesResponse) {
        try {
          rolesResponse = await fetchRoles(token, controller.signal);
        } catch {
          rolesResponse = null;
        }
      }

      const roleLookup = buildRoleLookup(rolesResponse ?? []);
      const { admins, assistants } = usersResponse
        ? countUsersByRole(usersResponse, roleLookup)
        : { admins: null, assistants: null };
      const rolesCount = rolesResponse
        ? rolesResponse.filter((role) => !role.is_system).length
        : null;

      setStats({
        admins,
        roles: rolesCount,
        assistants,
      });
    };

    loadUserRole();

    return () => controller.abort();
  }, []);

  const userMenuItems = React.useMemo(() => {
    if (hideRoleSection) {
      return baseUserMenuItems.filter((item) => item.id !== 'role');
    }
    return baseUserMenuItems;
  }, [hideRoleSection]);

  return (
    <>
      <PageHeader
        title="Gestion des utilisateurs"
        description="Gerez les comptes, les roles et les droits d'acces."
      />

      <section className="mt-6 grid gap-4 md:grid-cols-3">
        <Card
          padding="sm"
          className="group relative overflow-hidden border-border/70 border-l-4 border-l-primary/60 bg-gradient-to-br from-background via-background/80 to-primary/15 shadow-soft transition-all duration-300 ease-[var(--transition-smooth)] hover:-translate-y-1 hover:shadow-soft-lg"
        >
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.22),_transparent_55%)]" />
          <div className="pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full bg-primary/25 blur-2xl transition-opacity duration-300 group-hover:opacity-90" />
          <CardHeader className="relative space-y-2">
            <CardDescription className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground/80">
              Responsables (admin)
            </CardDescription>
            <CardTitle className="text-4xl font-semibold tracking-tight text-primary md:text-5xl">
              {formatStat(stats.admins)}
            </CardTitle>
            <p className="text-sm text-muted-foreground/80">Comptes avec privileges admin.</p>
          </CardHeader>
        </Card>
        <Card
          padding="sm"
          className="group relative overflow-hidden border-border/70 border-l-4 border-l-emerald-500/60 bg-gradient-to-br from-background via-background/80 to-emerald-500/15 shadow-soft transition-all duration-300 ease-[var(--transition-smooth)] hover:-translate-y-1 hover:shadow-soft-lg"
        >
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.22),_transparent_55%)]" />
          <div className="pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full bg-emerald-500/30 blur-2xl transition-opacity duration-300 group-hover:opacity-90" />
          <CardHeader className="relative space-y-2">
            <CardDescription className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground/80">
              Roles crees
            </CardDescription>
            <CardTitle className="text-4xl font-semibold tracking-tight text-emerald-500 md:text-5xl">
              {formatStat(stats.roles)}
            </CardTitle>
            <p className="text-sm text-muted-foreground/80">Roles personnalises disponibles.</p>
          </CardHeader>
        </Card>
        <Card
          padding="sm"
          className="group relative overflow-hidden border-border/70 border-l-4 border-l-sky-500/60 bg-gradient-to-br from-background via-background/80 to-sky-500/15 shadow-soft transition-all duration-300 ease-[var(--transition-smooth)] hover:-translate-y-1 hover:shadow-soft-lg"
        >
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.22),_transparent_55%)]" />
          <div className="pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full bg-sky-500/30 blur-2xl transition-opacity duration-300 group-hover:opacity-90" />
          <CardHeader className="relative space-y-2">
            <CardDescription className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground/80">
              Assistants
            </CardDescription>
            <CardTitle className="text-4xl font-semibold tracking-tight text-sky-500 md:text-5xl">
              {formatStat(stats.assistants)}
            </CardTitle>
            <p className="text-sm text-muted-foreground/80">Utilisateurs relies aux assistances.</p>
          </CardHeader>
        </Card>
      </section>

      <div className="mt-6 flex justify-center">
        <MiniMenu
          items={userMenuItems}
          ariaLabel="Menu utilisateurs"
          className="motion-safe:animate-soften-up-1"
        />
      </div>

      <div className="motion-safe:animate-soften-up-2">{children}</div>
    </>
  );
}
