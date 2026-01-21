'use client';

import { Plus } from 'lucide-react';

import {
  Button,
  Checkbox,
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Input,
  Label,
  Textarea,
} from '@/components';

import { rolePermissions } from '../data/role-permissions.data';

export function RoleFormDialog() {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button type="button" size="lg" className="items-center gap-3">
          <span className="flex items-center gap-3">
            <Plus className="h-5 w-5 translate-y-[1px]" aria-hidden="true" />
            <span className="whitespace-nowrap leading-tight">Ajouter un role</span>
          </span>
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[80vh] overflow-hidden p-6 sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>Creer un role</DialogTitle>
          <DialogDescription>
            Definissez un titre, une description et les permissions associees.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-5">
          <div className="max-h-[52vh] space-y-5 overflow-y-auto pr-3 scrollbar-subtle">
            <div className="space-y-2">
              <Label htmlFor="role-title">Titre du role</Label>
              <Input id="role-title" placeholder="Ex: Assistant" />
            </div>

            <div className="space-y-2">
              <Label htmlFor="role-description">Description</Label>
              <Textarea
                id="role-description"
                rows={3}
                placeholder="Decrivez les responsabilites principales."
              />
            </div>

            <div className="space-y-3 rounded-2xl border border-border/60 bg-surface/60 p-4">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-semibold text-foreground">Fonctionnalites</Label>
                <span className="text-xs text-muted-foreground">
                  Choisir les permissions
                </span>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                {rolePermissions.map((permission) => (
                  <div
                    key={permission.id}
                    className="flex items-start gap-3 rounded-xl border border-border/70 bg-background/40 px-3 py-2"
                  >
                    <Checkbox id={permission.id} />
                    <Label htmlFor={permission.id} className="space-y-1 text-sm">
                      <span className="font-medium text-foreground">
                        {permission.label}
                      </span>
                      {permission.description && (
                        <span className="block text-xs text-muted-foreground">
                          {permission.description}
                        </span>
                      )}
                    </Label>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter className="pt-2">
            <DialogClose asChild>
              <Button type="button" variant="ghost">
                Annuler
              </Button>
            </DialogClose>
            <Button type="submit">Enregistrer</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
