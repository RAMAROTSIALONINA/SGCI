import { Button, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components';
import type { UserRecord } from '@/types/user-record';

type UsersTableProps = {
  title: string;
  rows: UserRecord[];
  showDelete?: boolean;
};

export function UsersTable({ title, rows, showDelete = false }: UsersTableProps) {
  return (
    <section className="rounded-2xl border border-border/80 bg-background/60 p-6 shadow-soft">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-foreground">{title}</h2>
        <span className="text-xs text-muted-foreground">
          {rows.length} utilisateur{rows.length > 1 ? 's' : ''}
        </span>
      </div>

      <div className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Nom</TableHead>
              <TableHead>Prenom</TableHead>
              <TableHead>Email</TableHead>
              {showDelete && <TableHead className="text-right">Supprimer</TableHead>}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((user) => (
              <TableRow key={user.id}>
                <TableCell className="font-medium text-foreground">{user.lastName}</TableCell>
                <TableCell>{user.firstName}</TableCell>
                <TableCell className="text-muted-foreground">{user.email}</TableCell>
                {showDelete && (
                  <TableCell className="text-right">
                    {user.createdByAdmin ? (
                      <Button type="button" size="sm" variant="destructive">
                        Supprimer
                      </Button>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                )}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
