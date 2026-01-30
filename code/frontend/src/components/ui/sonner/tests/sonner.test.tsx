import { render } from '@testing-library/react';
import { beforeEach, describe, it, vi } from 'vitest';

import { Toaster } from '..';

describe('Toaster', () => {
  beforeEach(() => {
    if (!window.matchMedia) {
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: vi.fn().mockImplementation((query: string) => ({
          matches: false,
          media: query,
          onchange: null,
          addListener: vi.fn(),
          removeListener: vi.fn(),
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
          dispatchEvent: vi.fn(),
        })),
      });
    }
  });

  it('renders without crashing', () => {
    render(<Toaster />);
  });
});
