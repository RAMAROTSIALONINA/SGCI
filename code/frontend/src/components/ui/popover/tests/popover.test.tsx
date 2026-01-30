import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Button } from '../../button';
import { Popover, PopoverContent, PopoverTrigger } from '..';

describe('Popover', () => {
  it('opens on trigger click', async () => {
    render(
      <Popover>
        <PopoverTrigger asChild>
          <Button>Open popover</Button>
        </PopoverTrigger>
        <PopoverContent>
          <span>Popover content</span>
        </PopoverContent>
      </Popover>,
    );

    expect(screen.queryByText('Popover content')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Open popover'));

    expect(await screen.findByText('Popover content')).toBeInTheDocument();
  });
});
