import { describe, expect, it } from 'vitest';

import {
  formatRoleLabel,
  isAdminRole,
  isAssistantRole,
  isSuperAdminRole,
  normalizeRole,
  normalizeRoleCode,
} from './roles';

describe('roles helpers', () => {
  it('normalizes role codes', () => {
    expect(normalizeRoleCode(' Admin UBS ')).toBe('admin_ubs');
    expect(normalizeRoleCode(undefined)).toBe('');
  });

  it('normalizes role labels', () => {
    expect(normalizeRole('Super Admin')).toBe('super_admin');
    expect(normalizeRole('admin-ubs')).toBe('admin_ubs');
  });

  it('identifies admin roles', () => {
    expect(isSuperAdminRole('super_admin')).toBe(true);
    expect(isAdminRole('admin_ubs')).toBe(true);
    expect(isAdminRole('assistant')).toBe(false);
  });

  it('detects assistant roles', () => {
    expect(isAssistantRole('assistant', {})).toBe(true);
    expect(isAssistantRole('custom', { custom: { is_assistant: false } })).toBe(false);
    expect(isAssistantRole('custom', { custom: { is_assistant: true } })).toBe(true);
  });

  it('formats role labels', () => {
    expect(formatRoleLabel('super_admin')).toBe('Super Admin');
    expect(formatRoleLabel(null)).toBe('');
  });
});
