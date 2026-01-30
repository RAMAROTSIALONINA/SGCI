import type { Meta, StoryObj } from '@storybook/react';

import { RadioGroup, RadioGroupItem } from '.';

const meta: Meta<typeof RadioGroup> = {
  title: 'UI/RadioGroup',
  component: RadioGroup,
};

export default meta;
type Story = StoryObj<typeof RadioGroup>;

export const Default: Story = {
  render: () => (
    <RadioGroup defaultValue="a">
      <div className="flex items-center gap-3">
        <RadioGroupItem value="a" />
        <span className="text-sm">Option A</span>
      </div>
      <div className="flex items-center gap-3">
        <RadioGroupItem value="b" />
        <span className="text-sm">Option B</span>
      </div>
    </RadioGroup>
  ),
};

export const Sizes: Story = {
  render: () => (
    <RadioGroup defaultValue="sm">
      <div className="flex items-center gap-3">
        <RadioGroupItem value="sm" size="sm" />
        <span className="text-sm">Small</span>
      </div>
      <div className="flex items-center gap-3">
        <RadioGroupItem value="md" size="md" />
        <span className="text-sm">Medium</span>
      </div>
      <div className="flex items-center gap-3">
        <RadioGroupItem value="lg" size="lg" />
        <span className="text-sm">Large</span>
      </div>
    </RadioGroup>
  ),
};
