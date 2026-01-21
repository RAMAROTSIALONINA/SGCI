import { MiniMenu, PageHeader } from '@/components';

const userMenuItems = [
  { id: 'liste', label: 'Liste', href: '/gestion-des-utilisateurs/liste' },
  { id: 'role', label: 'Role', href: '/gestion-des-utilisateurs/role' },
  {
    id: 'nouvel-utilisateur',
    label: 'Nouveau',
    href: '/gestion-des-utilisateurs/nouvel-utilisateur',
  },
];

export default function UsersManagementLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <PageHeader
        title="Gestion des utilisateurs"
        description="Gerez les comptes, les roles et les droits d'acces."
      />

      <div className="mt-6 flex justify-center">
        <MiniMenu items={userMenuItems} ariaLabel="Menu utilisateurs" />
      </div>

      {children}
    </>
  );
}
