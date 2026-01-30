import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { Checkbox } from '..';

describe('Checkbox', () => {
  it('toggles checked state', async () => {
    const user = userEvent.setup();
    render(<Checkbox />);

    const checkbox = screen.getByRole('checkbox');
    await user.click(checkbox);
    expect(checkbox).toHaveAttribute('aria-checked', 'true');
  });
});
