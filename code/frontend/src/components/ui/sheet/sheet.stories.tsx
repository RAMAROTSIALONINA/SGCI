import type { Meta, StoryObj } from '@storybook/react';

import { Button } from '@/components/ui/button';

import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '.';

const meta: Meta<typeof Sheet> = {
  title: 'UI/Sheet',
  component: Sheet,
};

export default meta;
type Story = StoryObj<typeof Sheet>;

export const Default: Story = {
  render: () => (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="secondary">Ouvrir le sheet</Button>
      </SheetTrigger>
      <SheetContent side="right">
        <SheetHeader>
          <SheetTitle>Sheet premium</SheetTitle>
          <SheetDescription>Un panneau latéral élégant avec overlay doux.</SheetDescription>
        </SheetHeader>
        <div className="space-y-3">
          <label className="text-sm font-medium">
            Nom
            <input
              className="mt-1 w-full rounded-xl border border-border bg-surface-muted px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
              placeholder="Votre nom"
            />
          </label>
          <label className="text-sm font-medium">
            Message
            <textarea
              className="mt-1 w-full rounded-xl border border-border bg-surface-muted px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
              rows={3}
              placeholder="Bonjour..."
            />
          </label>
        </div>
        <SheetFooter>
          <SheetClose asChild>
            <Button variant="ghost">Annuler</Button>
          </SheetClose>
          <Button>Envoyer</Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  ),
};

export const FromLeft: Story = {
  render: () => (
    <Sheet defaultOpen>
      <SheetContent side="left">
        <SheetHeader>
          <SheetTitle>Menu latéral</SheetTitle>
          <SheetDescription>Navigation secondaire.</SheetDescription>
        </SheetHeader>
        <div className="space-y-2 text-sm text-muted-foreground">
          <p>Tableau de bord</p>
          <p>Paramètres</p>
          <p>Support</p>
        </div>
      </SheetContent>
    </Sheet>
  ),
};
