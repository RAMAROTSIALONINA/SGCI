import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '..';

describe('Accordion', () => {
  it('toggles content on trigger click', async () => {
    const user = userEvent.setup();
    render(
      <Accordion type="single" collapsible>
        <AccordionItem value="item-1">
          <AccordionTrigger>Question</AccordionTrigger>
          <AccordionContent>Reponse</AccordionContent>
        </AccordionItem>
      </Accordion>,
    );

    expect(screen.queryByText('Reponse')).not.toBeInTheDocument();
    await user.click(screen.getByText('Question'));
    expect(screen.getByText('Reponse')).toBeVisible();
  });
});
