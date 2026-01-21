import { RolesTable, RoleFormDialog, assistantRoles, defaultRoles } from '@/features/gestion-des-utilisateurs';

export default function UsersRolesPage() {
  return (
    <main className="mt-6 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
      <div className="flex items-center justify-start">
        <RoleFormDialog />
      </div>

      <div className="mt-6">
        <div className="space-y-6">
          <RolesTable title="Roles par defaut" rows={defaultRoles} />
          <RolesTable title="Roles assistants crees" rows={assistantRoles} />
        </div>
      </div>
    </main>
  );
}
