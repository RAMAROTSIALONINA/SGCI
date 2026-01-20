import type { Meta, StoryObj } from '@storybook/react';

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '.';

const meta: Meta<typeof Accordion> = {
  title: 'UI/Accordion',
  component: Accordion,
};

export default meta;
type Story = StoryObj<typeof Accordion>;

export const Default: Story = {
  render: () => (
    <Accordion type="single" collapsible>
      <AccordionItem value="item-1">
        <AccordionTrigger>Est-ce premium ?</AccordionTrigger>
        <AccordionContent>
          Oui, avec des transitions douces et une hierarchy typographique claire.
        </AccordionContent>
      </AccordionItem>
      <AccordionItem value="item-2">
        <AccordionTrigger>Compatible clavier ?</AccordionTrigger>
        <AccordionContent>
          Les interactions Radix restent intactes pour l&apos;accessibilite.
        </AccordionContent>
      </AccordionItem>
    </Accordion>
  ),
};
