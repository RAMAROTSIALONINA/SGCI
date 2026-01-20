import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { Switch } from '..';

describe('Switch', () => {
  it('toggles state when clicked', async () => {
    const user = userEvent.setup();
    render(<Switch />);

    const toggle = screen.getByRole('switch');
    await user.click(toggle);

    expect(toggle).toHaveAttribute('aria-checked', 'true');
  });
});
