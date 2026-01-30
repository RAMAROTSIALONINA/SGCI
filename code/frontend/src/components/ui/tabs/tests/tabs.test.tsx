import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { Tabs, TabsContent, TabsList, TabsTrigger } from '..';

describe('Tabs', () => {
  it('notifies value change when a tab is clicked', async () => {
    const handleChange = vi.fn();
    render(
      <Tabs defaultValue="a" onValueChange={handleChange}>
        <TabsList>
          <TabsTrigger value="a">Tab A</TabsTrigger>
          <TabsTrigger value="b">Tab B</TabsTrigger>
        </TabsList>
        <TabsContent value="a">Content A</TabsContent>
        <TabsContent value="b">Content B</TabsContent>
      </Tabs>,
    );

    expect(screen.getByText('Content A')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByText('Tab B'));
    expect(handleChange).toHaveBeenCalledWith('b');
  });
});
