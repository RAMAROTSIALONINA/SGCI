import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '..';
import { Button } from '../../button';

describe('Dialog', () => {
  it('opens and closes via trigger and close button', async () => {
    render(
      <Dialog>
        <DialogTrigger asChild>
          <button type="button">Open</button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Titre modal</DialogTitle>
            <DialogDescription>Description</DialogDescription>
          </DialogHeader>
          <DialogClose asChild>
            <Button>Close</Button>
          </DialogClose>
        </DialogContent>
      </Dialog>,
    );

    expect(screen.queryByText('Titre modal')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Open'));
    expect(await screen.findByText('Titre modal')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Close'));
    expect(screen.queryByText('Titre modal')).not.toBeInTheDocument();
  });
});
