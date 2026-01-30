'use client';
import type { ReactNode } from 'react';

import { MiniMenu, PageHeader } from '@/components';
const settingsMenuItems = [
  { id: 'apparence', label: 'Apparence', href: '/dashboard/settings/apparence' },
  { id: 'modification', label: 'Modifier mon profil', href: '/dashboard/settings/modification' },
];
export default function SettingsLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <PageHeader
        title="Settings"
        description="Gerez votre apparence et vos informations de compte."
      />
      <div className="mt-6 flex justify-center">
        <MiniMenu
          items={settingsMenuItems}
          ariaLabel="Menu settings"
          className="motion-safe:animate-soften-up-1"
        />
      </div>
      <div className="motion-safe:animate-soften-up-2">{children}</div>
    </>
  );
}
