import type { Meta, StoryObj } from '@storybook/react';

import { Label } from '.';

const meta: Meta<typeof Label> = {
  title: 'UI/Label',
  component: Label,
};

export default meta;
type Story = StoryObj<typeof Label>;

export const Default: Story = {
  render: () => <Label>Nom</Label>,
};

export const Sizes: Story = {
  render: () => (
    <div className="space-y-2">
      <Label size="sm">Small</Label>
      <Label size="md">Medium</Label>
      <Label size="lg">Large</Label>
    </div>
  ),
};

export const Muted: Story = {
  render: () => <Label tone="muted">Label secondaire</Label>,
};
