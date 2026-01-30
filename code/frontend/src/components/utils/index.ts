import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export * from './assert';
export * from './constants';
export * from './copy';
export * from './format';
export * from './logger';
export * from './reveal';
export * from './sleep';
export * from './slot';
export * from './types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
