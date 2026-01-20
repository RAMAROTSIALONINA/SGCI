import type { Meta, StoryObj } from '@storybook/react';

import { Button } from '@/components/ui/button';

import {
  Popover,
  PopoverAnchor,
  PopoverContent,
  PopoverTrigger,
} from '.';

const meta: Meta<typeof Popover> = {
  title: 'UI/Popover',
  component: Popover,
};

export default meta;
type Story = StoryObj<typeof Popover>;

export const Default: Story = {
  render: () => (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="secondary">Voir plus</Button>
      </PopoverTrigger>
      <PopoverContent>
        <div className="space-y-2">
          <p className="text-sm font-semibold">Carte rapide</p>
          <p className="text-sm text-muted-foreground">
            Un petit contenu contextuel avec fond doux et ombres premium.
          </p>
        </div>
      </PopoverContent>
    </Popover>
  ),
};

export const WithAnchor: Story = {
  render: () => (
    <div className="flex items-center gap-4">
      <Popover>
        <PopoverAnchor />
        <PopoverTrigger asChild>
          <Button size="sm">Ancré</Button>
        </PopoverTrigger>
        <PopoverContent padding="lg" sideOffset={10}>
          <p className="text-sm">Positionné avec anchor pour un alignement précis.</p>
        </PopoverContent>
      </Popover>
    </div>
  ),
};
