import type { Meta, StoryObj } from '@storybook/react';

import { Textarea } from '.';

const meta: Meta<typeof Textarea> = {
  title: 'UI/Textarea',
  component: Textarea,
  args: {
    placeholder: 'Décrivez votre besoin...',
  },
};

export default meta;
type Story = StoryObj<typeof Textarea>;

export const Default: Story = {};

export const Disabled: Story = {
  args: { disabled: true },
};

export const Error: Story = {
  args: { tone: 'error', placeholder: 'Message requis' },
};
