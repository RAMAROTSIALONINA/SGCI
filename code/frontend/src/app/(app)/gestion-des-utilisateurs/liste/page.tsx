import { UsersTable, admins, assistants, superAdmins } from '@/features/gestion-des-utilisateurs';

export default function UsersListPage() {
  return (
    <main className="mt-6 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
      <div className="space-y-6">
        <UsersTable title="Superadmin" rows={superAdmins} />
        <UsersTable title="Admins" rows={admins} />
        <UsersTable title="Assistants" rows={assistants} showDelete />
      </div>
    </main>
  );
}
