import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { ScrollArea } from '..';

describe('ScrollArea', () => {
  it('renders content inside viewport', () => {
    render(
      <ScrollArea className="h-20 w-20">
        <div>Content</div>
      </ScrollArea>,
    );

    expect(screen.getByText('Content')).toBeInTheDocument();
  });
});
