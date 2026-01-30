import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';

import { ThemeToggle } from '../theme-toggle';

const mockUseTheme = vi.hoisted(() => vi.fn());

vi.mock('next-themes', () => ({
  useTheme: mockUseTheme,
}));

describe('ThemeToggle', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("expose l'action light quand le theme est dark", async () => {
    const setTheme = vi.fn();
    mockUseTheme.mockReturnValue({ resolvedTheme: 'dark', setTheme });

    render(<ThemeToggle />);

    const button = await screen.findByRole('button');

    expect(button).toHaveAttribute('aria-label', 'Switch to light mode');
  });

  it('bascule vers "light" quand on clique depuis le theme dark', async () => {
    const user = userEvent.setup();
    const setTheme = vi.fn();
    mockUseTheme.mockReturnValue({ resolvedTheme: 'dark', setTheme });

    render(<ThemeToggle />);
    const button = await screen.findByRole('button');

    await user.click(button);

    expect(setTheme).toHaveBeenCalledWith('light');
  });

  it("expose l'action dark quand le theme est light et bascule au clic", async () => {
    const user = userEvent.setup();
    const setTheme = vi.fn();
    mockUseTheme.mockReturnValue({ resolvedTheme: 'light', setTheme });

    render(<ThemeToggle />);
    const button = await screen.findByRole('button');

    expect(button).toHaveAttribute('aria-label', 'Switch to dark mode');

    await user.click(button);
    expect(setTheme).toHaveBeenCalledWith('dark');
  });
});
