import type { ReactNode } from 'react';

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components';

import type { RoleRecord } from '../types/role-record';

type RolesTableProps = {
  title: string;
  rows: RoleRecord[];
  renderActions?: (role: RoleRecord) => ReactNode;
};

export function RolesTable({ title, rows, renderActions }: RolesTableProps) {
  return (
    <section className="rounded-2xl border border-border/80 bg-background/60 p-6 shadow-soft">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-foreground">{title}</h2>
        <span className="text-xs text-muted-foreground">
          {rows.length} role{rows.length > 1 ? 's' : ''}
        </span>
      </div>

      <div className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Role</TableHead>
              <TableHead>Description</TableHead>
              {renderActions ? <TableHead className="text-right">Actions</TableHead> : null}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((role) => (
              <TableRow key={role.id}>
                <TableCell className="font-medium text-foreground">{role.name}</TableCell>
                <TableCell className="text-muted-foreground">{role.description}</TableCell>
                {renderActions ? (
                  <TableCell className="text-right">{renderActions(role)}</TableCell>
                ) : null}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
