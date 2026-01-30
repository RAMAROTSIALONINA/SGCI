import type { Meta, StoryObj } from '@storybook/react';

import { ScrollArea } from '.';

const meta: Meta<typeof ScrollArea> = {
  title: 'UI/ScrollArea',
  component: ScrollArea,
};

export default meta;
type Story = StoryObj<typeof ScrollArea>;

export const Default: Story = {
  render: () => (
    <ScrollArea className="h-40 w-64">
      <div className="space-y-2 p-4 text-sm">
        {Array.from({ length: 12 }).map((_, index) => (
          <p key={index}>Ligne {index + 1}</p>
        ))}
      </div>
    </ScrollArea>
  ),
};
