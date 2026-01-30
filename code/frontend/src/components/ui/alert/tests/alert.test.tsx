import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Alert, AlertDescription, AlertTitle } from '..';

describe('Alert', () => {
  it('renders title and description', () => {
    render(
      <Alert>
        <AlertTitle>Notice</AlertTitle>
        <AlertDescription>Details</AlertDescription>
      </Alert>,
    );

    expect(screen.getByText('Notice')).toBeInTheDocument();
    expect(screen.getByText('Details')).toBeInTheDocument();
  });
});
