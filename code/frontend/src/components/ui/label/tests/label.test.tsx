import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Label } from '..';

describe('Label', () => {
  it('renders text content', () => {
    render(<Label>Field</Label>);
    expect(screen.getByText('Field')).toBeInTheDocument();
  });
});
