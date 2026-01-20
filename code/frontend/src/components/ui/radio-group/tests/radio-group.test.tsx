import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { RadioGroup, RadioGroupItem } from '..';

describe('RadioGroup', () => {
  it('selects a radio item', async () => {
    const user = userEvent.setup();
    render(
      <RadioGroup defaultValue="a">
        <RadioGroupItem value="a" />
        <RadioGroupItem value="b" />
      </RadioGroup>,
    );

    const radios = screen.getAllByRole('radio');
    await user.click(radios[1]);

    expect(radios[1]).toHaveAttribute('aria-checked', 'true');
  });
});
