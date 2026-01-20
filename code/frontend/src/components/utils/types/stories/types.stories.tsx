import type { Meta, StoryObj } from '@storybook/react';

const meta: Meta = {
  title: 'Utils/Types',
  parameters: {
    docs: {
      description: {
        story:
          'Typed helpers such as WithChildren, Nullable, and DeepPartial help keep props and utilities safe.',
      },
    },
  },
};

export default meta;

type Story = StoryObj;

export const Overview: Story = {
  render: () => (
    <div className="space-y-2 rounded-md border border-dashed p-4">
      <p>Use &apos;WithChildren&apos; to add children to a base props type.</p>
      <p>Use &apos;Nullable&apos; for values that can be null or undefined.</p>
      <p>Use &apos;DeepPartial&apos; to make nested objects optional.</p>
    </div>
  ),
};
