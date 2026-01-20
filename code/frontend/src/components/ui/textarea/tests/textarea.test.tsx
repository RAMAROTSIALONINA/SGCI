import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Textarea } from '..';

describe('Textarea', () => {
  it('accepts user input', () => {
    render(<Textarea placeholder="Message" />);
    const textarea = screen.getByPlaceholderText('Message') as HTMLTextAreaElement;

    fireEvent.change(textarea, { target: { value: 'Hello' } });

    expect(textarea.value).toBe('Hello');
  });

  it('is disabled when requested', () => {
    render(<Textarea placeholder="Disabled" disabled />);
    expect(screen.getByPlaceholderText('Disabled')).toBeDisabled();
  });
});
