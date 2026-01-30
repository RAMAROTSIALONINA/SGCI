import type { Meta, StoryObj } from '@storybook/react';

import { Button } from '@/components/ui/button';

import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '.';

const meta: Meta<typeof Tooltip> = {
  title: 'UI/Tooltip',
  component: Tooltip,
};

export default meta;
type Story = StoryObj<typeof Tooltip>;

export const Default: Story = {
  render: () => (
    <TooltipProvider delayDuration={0}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="secondary">Survoler</Button>
        </TooltipTrigger>
        <TooltipContent>Info premium</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  ),
};

export const Inverted: Story = {
  render: () => (
    <TooltipProvider delayDuration={0}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button>Infos</Button>
        </TooltipTrigger>
        <TooltipContent tone="inverted">Tooltip inversé</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  ),
};
