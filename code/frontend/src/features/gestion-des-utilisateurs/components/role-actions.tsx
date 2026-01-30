'use client';

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
  Button,
} from '@/components';

import type { RoleRecord } from '../types/role-record';
import { RoleEditDialog } from './role-edit-dialog';
import { RolePermissionsDialog } from './role-permissions-dialog';

type RoleActionsProps = {
  role: RoleRecord;
  canManage: boolean;
  onDelete?: (role: RoleRecord) => void | Promise<void>;
  onUpdated?: () => void;
};

export function RoleActions({ role, canManage, onDelete, onUpdated }: RoleActionsProps) {
  return (
    <div className="flex items-center justify-end gap-2">
      <RolePermissionsDialog role={role} />
      {canManage ? (
        <>
          <RoleEditDialog role={role} onUpdated={onUpdated} />
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button type="button" size="sm" variant="destructive">
                Supprimer
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Supprimer ce role ?</AlertDialogTitle>
                <AlertDialogDescription>
                  Etes-vous sur de vouloir supprimer {role.name} ? Cette action est definitive.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Annuler</AlertDialogCancel>
                <AlertDialogAction onClick={() => void onDelete?.(role)}>
                  Confirmer
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </>
      ) : null}
    </div>
  );
}
