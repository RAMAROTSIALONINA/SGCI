import type { Meta, StoryObj } from '@storybook/react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';

import { Toaster } from '.';

const meta: Meta<typeof Toaster> = {
  title: 'UI/Toaster',
  component: Toaster,
};

export default meta;
type Story = StoryObj<typeof Toaster>;

export const Default: Story = {
  render: () => (
    <div>
      <Button
        onClick={() =>
          toast('Action terminee', {
            description: 'Votre modification a ete enregistree.',
          })
        }
      >
        Lancer un toast
      </Button>
      <Toaster />
    </div>
  ),
};
