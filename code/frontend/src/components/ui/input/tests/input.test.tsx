import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Input } from '..';

describe('Input', () => {
  it('allows typing text', () => {
    render(<Input placeholder="Email" />);
    const input = screen.getByPlaceholderText('Email') as HTMLInputElement;

    fireEvent.change(input, { target: { value: 'hello@example.com' } });

    expect(input.value).toBe('hello@example.com');
  });

  it('applies disabled state', () => {
    render(<Input placeholder="Disabled" disabled />);
    const input = screen.getByPlaceholderText('Disabled');

    expect(input).toBeDisabled();
  });
});
