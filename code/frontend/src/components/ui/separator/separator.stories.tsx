import type { Meta, StoryObj } from '@storybook/react';

import { Separator } from '.';

const meta: Meta<typeof Separator> = {
  title: 'UI/Separator',
  component: Separator,
};

export default meta;
type Story = StoryObj<typeof Separator>;

export const Default: Story = {
  render: () => (
    <div className="space-y-4">
      <div>Section A</div>
      <Separator />
      <div>Section B</div>
    </div>
  ),
};

export const Vertical: Story = {
  render: () => (
    <div className="flex h-12 items-center gap-4">
      <span>A</span>
      <Separator orientation="vertical" />
      <span>B</span>
    </div>
  ),
};
