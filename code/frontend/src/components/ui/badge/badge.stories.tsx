import type { Meta, StoryObj } from '@storybook/react';

import { Badge } from '.';

const meta: Meta<typeof Badge> = {
  title: 'UI/Badge',
  component: Badge,
  args: {
    children: 'Nouveau',
  },
  argTypes: {
    variant: {
      control: 'select',
      options: ['default', 'secondary', 'muted', 'destructive', 'outline'],
    },
    tone: {
      control: 'select',
      options: [undefined, 'success', 'info', 'warning'],
    },
  },
};

export default meta;
type Story = StoryObj<typeof Badge>;

export const Primary: Story = {};

export const Secondary: Story = {
  args: { variant: 'secondary' },
};

export const Muted: Story = {
  args: { variant: 'muted' },
};

export const Destructive: Story = {
  args: { variant: 'destructive' },
};

export const Outline: Story = {
  args: { variant: 'outline' },
};

export const Tones: Story = {
  render: () => (
    <div className="flex flex-wrap items-center gap-2">
      <Badge tone="success">Succès</Badge>
      <Badge tone="info">Info</Badge>
      <Badge tone="warning">Alerte</Badge>
    </div>
  ),
};
