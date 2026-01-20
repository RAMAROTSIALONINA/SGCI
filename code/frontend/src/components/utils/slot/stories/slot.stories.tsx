import type { Meta, StoryObj } from '@storybook/react';

import { Slot } from '../slot';

const meta: Meta<typeof Slot> = {
  title: 'Utils/Slot',
  component: Slot,
};

export default meta;

type Story = StoryObj<typeof Slot>;

export const Default: Story = {
  args: { as: 'div' },
  render: (args) => (
    <Slot {...args} className="rounded-md border border-dashed p-4">
      Slot content rendered as a div
    </Slot>
  ),
};

export const AsChild: Story = {
  render: (args) => (
    <Slot {...args} asChild>
      <button className="rounded-md bg-primary px-4 py-2 text-primary-foreground">
        Button rendered through Slot
      </button>
    </Slot>
  ),
};
