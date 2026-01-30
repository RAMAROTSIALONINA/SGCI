import { DEFAULT_CURRENCY, DEFAULT_LOCALE } from '../constants';

type DateInput = Date | string | number;

const toDate = (value: DateInput) => {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

export function formatDate(
  value: DateInput,
  options?: Intl.DateTimeFormatOptions,
  locale = DEFAULT_LOCALE,
) {
  const date = toDate(value);
  if (!date) return '';

  return new Intl.DateTimeFormat(locale, options).format(date);
}

export function formatNumber(
  value: number,
  options?: Intl.NumberFormatOptions,
  locale = DEFAULT_LOCALE,
) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '';

  return new Intl.NumberFormat(locale, options).format(value);
}

export function formatCurrency(
  value: number,
  currency = DEFAULT_CURRENCY,
  locale = DEFAULT_LOCALE,
  options?: Intl.NumberFormatOptions,
) {
  return formatNumber(value, { style: 'currency', currency, ...options }, locale);
}
