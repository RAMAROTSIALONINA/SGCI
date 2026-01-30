import type { Meta, StoryObj } from '@storybook/react';
import * as React from 'react';

import { Button } from '@/components/ui/button';

import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '.';

const meta: Meta<typeof Dialog> = {
  title: 'UI/Dialog',
  component: Dialog,
};

export default meta;
type Story = StoryObj<typeof Dialog>;

const Template = () => {
  const [open, setOpen] = React.useState(false);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="secondary">Ouvrir le dialogue</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Dialog premium</DialogTitle>
          <DialogDescription>
            Un overlay doux, des coins arrondis généreux et un focus clair.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <label className="block text-sm font-medium text-foreground/80">
            Email
            <input
              className="mt-1 w-full rounded-xl border border-border bg-surface-muted px-3 py-2 text-sm outline-none transition-colors focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/60"
              placeholder="vous@example.com"
            />
          </label>
          <label className="block text-sm font-medium text-foreground/80">
            Message
            <textarea
              className="mt-1 w-full rounded-xl border border-border bg-surface-muted px-3 py-2 text-sm outline-none transition-colors focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/60"
              rows={4}
              placeholder="Expliquez votre besoin..."
            />
          </label>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Annuler</Button>
          </DialogClose>
          <Button>Envoyer</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export const Default: Story = {
  render: () => <Template />,
};

export const WithLongContent: Story = {
  render: () => (
    <Dialog defaultOpen>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Conditions</DialogTitle>
          <DialogDescription>Exemple de contenu plus dense avec scroll minimal.</DialogDescription>
        </DialogHeader>
        <div className="space-y-2 text-sm text-muted-foreground">
          {Array.from({ length: 6 }).map((_, index) => (
            <p key={index}>
              Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus finibus, sapien vitae
              suscipit feugiat, arcu magna convallis orci, vitae tempus ligula lacus non erat.
            </p>
          ))}
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="secondary">Fermer</Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  ),
};
