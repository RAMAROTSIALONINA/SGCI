import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '..';

describe('Sheet', () => {
  it('opens on trigger interaction', async () => {
    render(
      <Sheet>
        <SheetTrigger asChild>
          <button type="button">Open sheet</button>
        </SheetTrigger>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Panel</SheetTitle>
            <SheetDescription>Détails</SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>,
    );

    expect(screen.queryByText('Panel')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Open sheet'));

    expect(await screen.findByText('Panel')).toBeInTheDocument();
  });
});
