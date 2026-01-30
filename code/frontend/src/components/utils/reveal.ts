import type { CSSProperties } from 'react';

type RevealStyleOptions = {
  delay?: number | string;
  offset?: number | string;
};

type RevealStyle = CSSProperties & {
  [key: `--${string}`]: string | undefined;
};

export function getRevealStyle({ delay, offset }: RevealStyleOptions): CSSProperties | undefined {
  if (delay == null && offset == null) return undefined;

  const style: RevealStyle = {};

  if (delay != null) {
    style['--reveal-delay'] = typeof delay === 'number' ? `${delay}ms` : delay;
  }

  if (offset != null) {
    style['--reveal-offset'] = typeof offset === 'number' ? `${offset}px` : offset;
  }

  return style;
}
