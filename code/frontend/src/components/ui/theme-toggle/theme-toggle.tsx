"use client";

import * as React from "react";
import {useTheme} from "next-themes";

const SunIcon = ({className}: {className?: string}) => (
  <svg
    aria-hidden="true"
    viewBox="0 0 24 24"
    className={className}
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <circle cx="12" cy="12" r="4.5" />
    <path d="M12 3.5v2.5M12 18v2.5M3.5 12h2.5M18 12h2.5" />
    <path d="M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8" />
    <path d="M18.4 5.6l-1.8 1.8M7.4 16.6l-1.8 1.8" />
  </svg>
);

const MoonIcon = ({className}: {className?: string}) => (
  <svg
    aria-hidden="true"
    viewBox="0 0 24 24"
    className={className}
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M20 14.5a8 8 0 0 1-10.5-10 7.5 7.5 0 1 0 10.5 10Z" />
  </svg>
);

export function ThemeToggle() {
  const {resolvedTheme, setTheme} = useTheme();
  const [mounted, setMounted] = React.useState(false);
  const [animate, setAnimate] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const theme = resolvedTheme ?? "light";
  const isDark = theme === "dark";

  React.useEffect(() => {
    if (!mounted) return;
    setAnimate(true);
    const timer = window.setTimeout(() => setAnimate(false), 520);
    return () => window.clearTimeout(timer);
  }, [isDark, mounted]);

  if (!mounted) {
    // Avoid server/client text mismatch by not rendering until mounted
    return null;
  }

  return (
    <button
      type="button"
      aria-pressed={isDark}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      onClick={() => setTheme(isDark ? "light" : "dark")}
      data-animate={animate ? "true" : undefined}
      data-theme={isDark ? "dark" : "light"}
      className="theme-toggle relative inline-flex h-9 w-[72px] items-center rounded-full border border-border/70 bg-surface/80 p-1 shadow-soft transition-colors duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    >
      <span
        className="theme-toggle__ripple"
        aria-hidden="true"
      />
      <span
        className={`absolute inset-1 rounded-full bg-gradient-to-r from-amber-200/80 via-rose-200/70 to-sky-200/80 transition-opacity duration-300 ${
          isDark ? "opacity-0" : "opacity-100"
        }`}
        aria-hidden="true"
      />
      <span
        className={`absolute inset-1 rounded-full bg-gradient-to-r from-slate-900/90 via-slate-800/90 to-slate-700/90 transition-opacity duration-300 ${
          isDark ? "opacity-100" : "opacity-0"
        }`}
        aria-hidden="true"
      />
      <span
        className={`theme-toggle__thumb relative z-10 flex h-7 w-7 items-center justify-center rounded-full border border-border/60 bg-white text-amber-500 shadow-soft transition-transform duration-300 ${
          isDark
            ? "translate-x-9 bg-slate-900 text-slate-100"
            : "translate-x-0"
        }`}
      >
        <SunIcon
          className={`h-4 w-4 transition-all duration-200 ${
            isDark ? "scale-75 opacity-0" : "scale-100 opacity-100"
          }`}
        />
        <MoonIcon
          className={`absolute h-4 w-4 transition-all duration-200 ${
            isDark ? "scale-100 opacity-100" : "scale-75 opacity-0"
          }`}
        />
      </span>
      <span className="sr-only">Toggle theme</span>
    </button>
  );
}
