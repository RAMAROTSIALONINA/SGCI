import { describe, expect, it } from 'vitest';

import { formatDateTimeShort } from './formatters';

describe('formatters', () => {
  it('returns empty string for invalid values', () => {
    expect(formatDateTimeShort(undefined)).toBe('');
    expect(formatDateTimeShort(null)).toBe('');
    expect(formatDateTimeShort('not-a-date')).toBe('');
  });

  it('formats valid dates', () => {
    const result = formatDateTimeShort('2024-01-01T10:00:00Z');
    expect(result).toBeTypeOf('string');
    expect(result.length).toBeGreaterThan(0);
  });
});
