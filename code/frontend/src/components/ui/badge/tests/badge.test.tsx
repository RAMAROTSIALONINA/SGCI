import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Badge } from '..';

describe('Badge', () => {
  it('renders with default variant', () => {
    render(<Badge>Label</Badge>);
    expect(screen.getByText('Label')).toBeInTheDocument();
  });

  it('applies tone modifiers', () => {
    render(<Badge tone="success">Ok</Badge>);
    expect(screen.getByText('Ok')).toHaveAttribute('class');
  });
});
