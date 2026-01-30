import '../src/app/globals.css';

import type { Preview } from '@storybook/react';
import React from 'react';

import { ThemeProvider } from '../src/components/providers/theme-provider';

const preview: Preview = {
  parameters: {
    actions: { argTypesRegex: '^on[A-Z].*' },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
  decorators: [
    (Story) => (
      <ThemeProvider attribute="class" defaultTheme="light">
        <div className="min-h-screen bg-background font-sans text-foreground antialiased">
          <Story />
        </div>
      </ThemeProvider>
    ),
  ],
};

export default preview;
