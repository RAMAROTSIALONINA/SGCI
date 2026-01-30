import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '..';

describe('DropdownMenu', () => {
  it('opens on trigger click', async () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button type="button">Open menu</button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Item A</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    expect(screen.queryByText('Item A')).not.toBeInTheDocument();
    fireEvent.pointerDown(screen.getByText('Open menu'));

    expect(await screen.findByText('Item A')).toBeInTheDocument();
  });
});
